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
"""

import base64
import inspect
import hvac
from dy_logging import logger
from dy_trace import trace_enter, trace_exit, CAMOUFLAGE_SIGN
import config


def __get_vault_client() -> hvac.Client:
    trace_enter(inspect.currentframe())

    vault_mtls_client_cert = config.get_config_by_keypath(
        'VAULT_MTLS_CLIENT_CERT')
    vault_mtls_client_key = config.get_config_by_keypath(
        'VAULT_MTLS_CLIENT_KEY')
    vault_url = config.get_config_by_keypath('VAULT_URL')

    mtls_auth = (vault_mtls_client_cert, vault_mtls_client_key)

    try:
        if vault_ca_cert := config.get_config_by_keypath('VAULT_CACERT'):
            client = hvac.Client(cert=mtls_auth, url=vault_url,
                                 verify=vault_ca_cert)
        else:
            client = hvac.Client(cert=mtls_auth, url=vault_url, verify=True)
    except Exception as exc:
        ret = None
        logger.error('Failed to create hvac client: %s', exc)
        trace_exit(inspect.currentframe(), ret)
        return ret

    trace_exit(inspect.currentframe(), client)
    return client


def __authenticate_vault_client(client: hvac.Client, tenant: str,
                                priv_jwt_token: str) -> hvac.Client:
    trace_enter(inspect.currentframe())

    vault_auth_jwt_path = config.get_vault_auth_jwt_path_by_tenant(tenant)

    logger.debug('Attempting to authenticate against Vault using JWT: %s',
                 priv_jwt_token)

    try:
        response = client.auth.jwt.jwt_login(
            role=config.get_vault_default_role_by_tenant(tenant),
            jwt=priv_jwt_token,
            path=vault_auth_jwt_path)
    except Exception as exc:
        ret = None
        logger.error('Failed to authenticate against Vault: %s', exc)
        trace_exit(inspect.currentframe(), ret)
        return ret

    logger.debug('Vault login response: %s', response)

    try:
        vault_token = response['auth']['client_token']
    except KeyError as exc:
        ret = None

        logger.error('Failed to access Vault token from auth response: %s. '
                     'This is most likely a permission issue.',
                     exc)

        trace_exit(inspect.currentframe(), ret)
        return ret

    if config.get_config_by_keypath('DEV_MODE'):
        logger.debug('Vault client token returned: %s', vault_token)

    client.token = vault_token

    if not client.is_authenticated():
        ret = None

        logger.error('Attempt to authenticate against Vault failed. '
                     'Review configuration (config/config.json).')

        trace_exit(inspect.currentframe(), ret)
        return ret

    trace_exit(inspect.currentframe(), client)
    return client


def get_dynamic_secret(tenant: str, key: str, key_version: str,
                       priv_jwt_token: str) -> bytearray:
    """Fetches dynamic secret from Vault."""
    trace_enter(inspect.currentframe())

    vault_transit_path = config.get_vault_transit_path_by_tenant(tenant)
    vault_url = config.get_config_by_keypath('VAULT_URL')

    client = __get_vault_client()
    if not client:
        ret = bytearray()
        logger.error('Failed to get Vault client.')
        trace_exit(inspect.currentframe(), ret)
        return ret

    client = __authenticate_vault_client(client, tenant, priv_jwt_token)
    if not client:
        ret = bytearray()
        logger.error('Failed to authenticate against Vault.')
        trace_exit(inspect.currentframe(), ret)
        return ret

    if not client.sys.is_initialized():
        ret = bytearray()
        logger.error('Vault at "%s" has not been initialized.', vault_url)
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

            logger.error('Failed to access key version in Vault key read '
                         'response: %s', exc)

            trace_exit(inspect.currentframe(), ret)
            return ret

    # fetch key
    try:
        response = client.secrets.transit.export_key(
            name=key, key_type='encryption-key', version=key_version,
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

        logger.error('Failed to get key material from response: %s',
                     exc)

        trace_exit(inspect.currentframe(), ret)
        return ret

    # delete sensitive data from memory
    del bytearray_b64_key[:]

    trace_exit(inspect.currentframe(), CAMOUFLAGE_SIGN)
    return bytearray_key
