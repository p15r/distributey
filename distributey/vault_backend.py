"""
Interacts with Vault.

Security Note:

HVAC, and requests respectively, store the exported secret in memory as
(immutable) string and can therefore not be safely erased from memory:
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
from dy_trace import trace_enter, trace_exit
import config


def get_dynamic_secret(tenant: str, key: str, key_version: str,
                       jwt_token: str) -> bytes:
    trace_enter(inspect.currentframe())

    vault_url = config.get_config_by_key('VAULT_URL')
    vault_auth_jwt_path = config.get_vault_auth_jwt_path_by_tenant(tenant)
    vault_transit_path = config.get_vault_transit_path_by_tenant(tenant)

    vault_mtls_client_cert = config.get_config_by_key('VAULT_MTLS_CLIENT_CERT')
    vault_mtls_client_key = config.get_config_by_key('VAULT_MTLS_CLIENT_KEY')

    mtls_auth = (vault_mtls_client_cert, vault_mtls_client_key)

    if vault_ca_cert := config.get_config_by_key('VAULT_CACERT'):
        client = hvac.Client(cert=mtls_auth, url=vault_url,
                             verify=vault_ca_cert)
    else:
        client = hvac.Client(cert=mtls_auth, url=vault_url, verify=True)

    logger.debug('Attempting to authenticate against Vault using JWT: %s',
                 jwt_token)

    response = client.auth.jwt.jwt_login(
        role=config.get_vault_default_role_by_tenant(tenant),
        jwt=jwt_token,
        path=vault_auth_jwt_path)

    logger.debug('Vault login response: %s', response)

    # TODO: hier noch ein check: client.is_authenticated()?

    vault_token = response['auth']['client_token']

    if config.get_config_by_key('DEV_MODE'):
        logger.debug('Vault client token returned: %s', vault_token)

    if vault_ca_cert := config.get_config_by_key('VAULT_CACERT'):
        client = hvac.Client(cert=mtls_auth, url=vault_url, token=vault_token,
                             verify=vault_ca_cert)
    else:
        client = hvac.Client(cert=mtls_auth, url=vault_url, token=vault_token,
                             verify=True)

    if not client.sys.is_initialized():
        logger.error('Vault at "%s" has not been initialized.', vault_url)
        trace_exit(inspect.currentframe(), b'')
        return b''

    # fetch most recent key version of key
    response = client.secrets.transit.read_key(name=key,
                                               mount_point=vault_transit_path)

    if key_version == 'latest':
        key_version = response['data']['latest_version']

    # fetch key
    response = client.secrets.transit.export_key(
        name=key, key_type='encryption-key', version=key_version,
        mount_point=vault_transit_path)

    b64_key = response['data']['keys'][str(key_version)]

    ret = base64.b64decode(b64_key)
    trace_exit(inspect.currentframe(), ret)
    return ret
