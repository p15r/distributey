"""
Retrieves dynamic secrets from Vault.

Security Note:

HVAC, and requests respectively, store exported secrets in-memory as
immutable strings and can therefore not be safely erased from memory:
- https://github.com/hvac/hvac/blob/b9343973307eaba1bbe28ebf9e1911520ffcbf0a/
      hvac/api/secrets_engines/transit.py#L274
- https://github.com/hvac/hvac/blob/b9343973307eaba1bbe28ebf9e1911520ffcbf0a/
    hvac/adapters.py#L94
- https://github.com/hvac/hvac/blob/b9343973307eaba1bbe28ebf9e1911520ffcbf0a/
    hvac/adapters.py#L287

Vault Token Cache Note:
Token expiration (TTL) is disregarded. In worst case scenario,
every cache contains an expired token for a JWT KID. This would lead to
"N worker processes + 1" HYOK request attempts to successfully authenticate.
"""

import base64
import inspect
from typing import Dict
import hvac
from dy_logging import logger
from dy_trace import trace_enter, trace_exit, CAMOUFLAGE_SIGN
import config
import utils

# In-memory cache, per gunicorn worker process, for Vault JWT tokens.
# Because HYOK requests are stateless (no cookies), access to any
# of the caches is random and so are cache hits/misses.
__VAULT_TOKEN_CACHE: Dict[str, str] = {}


def __get_vault_client(tenant: str) -> hvac.Client:
    vault_mtls_client_cert = config.get_vault_mtls_client_cert(tenant)
    vault_mtls_client_key = config.get_vault_mtls_client_key(tenant)
    vault_url = config.get_vault_url(tenant)
    vault_ns = config.get_vault_namespace(tenant)
    vault_ca_cert = config.get_vault_ca_cert(tenant)

    if not vault_mtls_client_cert:
        logger.error('Failed to load Vault mTLS client cert.')
        return None
    if not vault_mtls_client_key:
        logger.error('Failed to load Vault mTLS client key.')
        return None
    if not vault_url:
        logger.error('Failed to load Vault url.')
        return None
    if not vault_ns:
        logger.error('Failed to load Vault namespace')
        return None
    if not vault_ca_cert:
        logger.warning('Failed to load Vault CA cert.')
        verify=True
    else:
        verify=vault_ca_cert

    if vault_ns == 'root':
        vault_ns = ''

    mtls_auth = (vault_mtls_client_cert, vault_mtls_client_key)

    # hvac.Client() never raises exceptions, regardless of the parameters
    client = hvac.Client(
                cert=mtls_auth,
                url=vault_url,
                namespace=vault_ns,
                verify=verify
    )

    trace_exit(inspect.currentframe(), client)
    return client


def __get_vault_token(
        client: hvac.Client,
        tenant: str,
        priv_jwt_token: str,
        vault_auth_jwt_path: str,
        cache_client_id: str) -> str:

    trace_enter(inspect.currentframe())

    default_role = config.get_vault_default_role(tenant)

    if not default_role:
        logger.error(
            'Failed to load Vault default role for tenant "%s"', tenant
        )
        return ''

    try:
        response = client.auth.jwt.jwt_login(
            role=default_role,
            jwt=priv_jwt_token,
            path=vault_auth_jwt_path)
    except Exception as exc:
        ret = ''
        logger.error('Failed to authenticate against Vault: %s', exc)
        trace_exit(inspect.currentframe(), ret)
        return ret

    if config.get_config_by_keypath('DEV_MODE'):
        logger.debug('Vault login response: %s', response)

    try:
        vault_token = response['auth']['client_token']
    except KeyError as exc:
        ret = ''

        logger.error(
            'Failed to access the Vault token from auth response: '
            'KeyError on key %s. '
            'This is most likely a permission issue.',
            exc)

        trace_exit(inspect.currentframe(), ret)
        return ret

    if config.get_config_by_keypath('DEV_MODE'):
        logger.debug('Vault client token returned: %s', vault_token)

    logger.debug('Retrieved new Vault token.')

    __VAULT_TOKEN_CACHE[cache_client_id] = vault_token

    trace_exit(inspect.currentframe(), CAMOUFLAGE_SIGN)
    return vault_token


def __authenticate_vault_client(
        client: hvac.Client,
        tenant: str,
        priv_jwt_token: str) -> hvac.Client:

    trace_enter(inspect.currentframe())

    vault_auth_jwt_path = config.get_vault_auth_jwt_path(tenant)

    if not vault_auth_jwt_path:
        logger.error('Failed to load auth jwt path for tenant "%s"', tenant)
        return None

    if config.get_config_by_keypath('DEV_MODE'):
        logger.debug(
            'Attempting to authenticate against Vault using JWT: %s',
            priv_jwt_token)

    cache_client_id = utils.get_kid_from_jwt(priv_jwt_token)

    if cache_client_id in __VAULT_TOKEN_CACHE:
        logger.debug(
            'Cache hit: Found token for "%s".', cache_client_id)
        client.token = __VAULT_TOKEN_CACHE[cache_client_id]
    else:
        logger.debug(
            'Cache miss: Token for "%s" not found.', cache_client_id)

        token = __get_vault_token(
            client,
            tenant,
            priv_jwt_token,
            vault_auth_jwt_path,
            cache_client_id)

        if not token:
            ret = None
            logger.error('Failed to get Vault token.')
            trace_exit(inspect.currentframe(), ret)
            return ret

        client.token = token

    if not client.is_authenticated():
        # token might be invalid/has expired
        del __VAULT_TOKEN_CACHE[cache_client_id]

        ret = None

        logger.error(
            'Failed to validate Vault client. '
            'Review configuration (config/config.json). '
            'Retry as token might have expired.')

        trace_exit(inspect.currentframe(), ret)
        return ret

    logger.debug(
        'Successfully authenticated Vault client '
        'for tenant "%s"', tenant)

    trace_exit(inspect.currentframe(), client)
    return client


def get_dynamic_secret(
        tenant: str, key: str, key_version: str,
        priv_jwt_token: str) -> bytearray:
    """Fetches dynamic secret from Vault."""

    trace_enter(inspect.currentframe())

    vault_transit_path = config.get_vault_transit_path(tenant)

    if not vault_transit_path:
        logger.error(
            'Failed to load Vault transit path for tenant "%s"', tenant
        )
        return b''

    client = __get_vault_client(tenant)
    if not client:
        ret = bytearray()
        logger.error('Failed to get Vault client.')
        trace_exit(inspect.currentframe(), ret)
        return ret

    client = __authenticate_vault_client(client, tenant, priv_jwt_token)
    if not client:
        ret = bytearray()
        logger.error('Failed to authenticate Vault client.')
        trace_exit(inspect.currentframe(), ret)
        return ret

    # fetch most recent key version of key
    try:
        response = client.secrets.transit.read_key(
            name=key, mount_point=vault_transit_path)
    except hvac.exceptions.Forbidden as exc:
        ret = bytearray()
        logger.error('Insufficient permissions to access secret: %s', exc)
        trace_exit(inspect.currentframe(), ret)
        return ret

    if key_version == 'latest':
        try:
            key_version = response['data']['latest_version']
        except KeyError as exc:
            ret = bytearray()

            logger.error(
                'Failed to access key version in Vault key read '
                'response: %s', exc)

            trace_exit(inspect.currentframe(), ret)
            return ret

    # fetch key
    try:
        response = client.secrets.transit.export_key(
            name=key,
            key_type='encryption-key',
            version=key_version,
            mount_point=vault_transit_path)
    except Exception as exc:
        ret = bytearray()
        logger.error('Failed to export key: %s ', exc)
        trace_exit(inspect.currentframe(), ret)
        return ret

    try:
        bytearray_b64_key = bytearray(
            response['data']['keys'][str(key_version)].encode())

        bytearray_key = bytearray(base64.b64decode(bytearray_b64_key))
    except Exception as exc:
        ret = bytearray()

        logger.error(
            'Failed to get key material from response: %s', exc)

        trace_exit(inspect.currentframe(), ret)
        return ret

    # delete sensitive data from memory
    del bytearray_b64_key[:]

    trace_exit(inspect.currentframe(), CAMOUFLAGE_SIGN)
    return bytearray_key
