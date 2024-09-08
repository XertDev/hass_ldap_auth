import logging
from collections import OrderedDict

from typing import cast, Any, Mapping

import ldap3

import voluptuous as vol
from homeassistant.auth import LoginFlow, InvalidAuthError, GROUP_ID_ADMIN, EVENT_USER_ADDED
from homeassistant.auth.const import GROUP_ID_USER
from homeassistant.auth.models import Credentials, UserMeta
from homeassistant.auth.providers import AUTH_PROVIDERS, AuthProvider
import homeassistant.helpers.config_validation as cv
from homeassistant.components.person import async_create_person
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

_LOGGER = logging.getLogger(__name__)

DOMAIN = "ldap_auth"

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Required("ldap_address"): cv.string,
                vol.Required("users_dn"): cv.string,
                vol.Required("user_filter"): cv.string,
                vol.Required("admin_filter"): cv.string,
            }
        )
    },
    extra=vol.ALLOW_EXTRA
)


class InvalidAuth(HomeAssistantError):
    """Raised when we encounter invalid authentication (wrong credentials, problem with provider)"""


class InsufficientPermissions(HomeAssistantError):
    """Raised when we encounter insufficient permissions"""


async def async_setup(hass: HomeAssistant, config):
    # Auth provider
    providers = OrderedDict()
    provider = LDAPAuthProvider(
        hass,
        hass.auth._store,
        config[DOMAIN]
    )

    providers[(provider.type, provider.id)] = provider
    providers.update(hass.auth._providers)
    hass.auth._providers = providers

    _LOGGER.info("LDAP auth initialized")
    return True


@AUTH_PROVIDERS.register("ldap")
class LDAPAuthProvider(AuthProvider):
    DEFAULT_TITLE = "LDAP Authentication"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._user_meta: dict[str, dict[str, Any]] = {}

        self._server = ldap3.Server(self.config["ldap_address"])

    @property
    def type(self) -> str:
        return "ldap"

    @property
    def support_mfa(self) -> bool:
        return False

    async def _async_create_user_from_ldap(self, credentials: Credentials):
        user = await self.store.async_create_user(
            credentials=credentials,
            name=self._user_meta["name"],
            is_active=True,
            is_owner=self._user_meta["admin"],
            group_ids=[GROUP_ID_ADMIN if self._user_meta["admin"] else GROUP_ID_USER],
            system_generated=False,
            local_only=False
        )
        _LOGGER.info("Created user: %s", self._user_meta["name"])

        await async_create_person(self.hass, user.name, user_id=user.id)
        _LOGGER.info("Created person: %s", self._user_meta["name"])
        self.hass.bus.async_fire(EVENT_USER_ADDED, {"user_id": user.id})

    async def async_get_or_create_credentials(
        self, flow_result: Mapping[str, str]
    ) -> Credentials:
        username = flow_result["username"]
        for credentials in await self.async_credentials():
            if credentials.data["username"] == username:
                _LOGGER.debug("Found existing credentials for user: %s", username)
                return credentials

        # Let's create user
        credentials = self.async_create_credentials({"username": username})
        await self._async_create_user_from_ldap(credentials)
        credentials.is_new = False

        return credentials

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        raise NotImplementedError("User should be created while fetching credentials")

    async def async_login_flow(self, context: dict[str, Any] | None) -> LoginFlow:
        return LdapAuthLoginFlow(self)

    def _user_dn(self, username: str):
        return f"uid={username},{self.config['users_dn']}"

    def _user_access_query(self, username: str):
        user_filter = self.config["user_filter"].format(username=username)
        admin_filter = self.config["admin_filter"].format(username=username)
        return "(|{user}{admin})".format(user=user_filter, admin=admin_filter)

    def _user_admin_query(self, username: str):
        return self.config["admin_filter"].format(username=username)

    def _query_user_meta(self, connection: ldap3.Connection, username: str, user_dn: str):
        status, result, response, _ = connection.search(user_dn, self._user_access_query(username),
                                                        attributes=["uid", "displayName"])

        if not status:
            if result["description"] == "success":
                _LOGGER.error("User %r has insufficient permissions", username)
                raise InsufficientPermissions("Insufficient permissions")
            else:
                _LOGGER.error("LDAP error")
                raise InvalidAuthError("Communication with LDAP failed")

        if len(response) != 1:
            _LOGGER.error("Invalid ldap response. Please check user_filter.")
            raise InvalidAuthError("Communication with LDAP failed")

        response = response[0]
        self._user_meta["name"] = response["attributes"]["uid"][0]
        if "displayName" in response["attributes"] and response["attributes"]["displayName"]:
            self._user_meta["name"] = response["attributes"]["displayName"]

        status, result, response, _ = connection.search(user_dn, self._user_admin_query(username))
        if not status:
            if result["description"] != "success":
                _LOGGER.error("LDAP error")
                raise InvalidAuthError("Communication with LDAP failed")

        if len(response) > 1:
            _LOGGER.error("Invalid ldap response. Please check user_filter.")
            raise InvalidAuthError("Communication with LDAP failed")

        self._user_meta["admin"] = False
        if len(response) == 1:
            self._user_meta["admin"] = True

    def _query_user_by_bind(self, username: str, password: str):
        user_dn = self._user_dn(username)
        connection = ldap3.Connection(self._server, user_dn, password, client_strategy=ldap3.SAFE_SYNC)
        _LOGGER.debug("Trying to bind user %r", user_dn)
        status, _, _, _ = connection.bind()
        if not status:
            _LOGGER.error("User %r failed to authenticate", username)
            raise InvalidAuth("User does not exists")

        _LOGGER.debug("User %r bound succesfully", user_dn)

        self._query_user_meta(connection, username, user_dn)

    async def async_full_login(self, username: str, password: str):
        await self.hass.async_add_executor_job(self._query_user_by_bind, username, password)


class LdapAuthLoginFlow(LoginFlow):
    def __init__(
            self,
            auth_provider: LDAPAuthProvider
    ) -> None:
        super().__init__(auth_provider)

    async def async_step_init(self, user_input=None):
        errors = {}

        if user_input is not None:
            user_input["username"] = user_input["username"]
            try:
                await cast(
                    LDAPAuthProvider, self._auth_provider
                ).async_full_login(user_input["username"], user_input["password"])
            except InvalidAuth:
                _LOGGER.debug("Username & password authorization failed")
                errors["base"] = "invalid_auth"
            except (InvalidAuthError, InsufficientPermissions):
                errors["base"] = "invalid_auth"

            if not errors:
                user_input.pop("password")
                return await self.async_finish(user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required("username"): str,
                    vol.Required("password"): str,
                }
            ),
            errors=errors,
        )
