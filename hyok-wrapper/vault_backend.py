"""
Security Note:

HVAC, and requests respectively, store the exported secret in memory as
(immutable) string and can therefore not be safely erased from memory:
- https://github.com/hvac/hvac/blob/b9343973307eaba1bbe28ebf9e1911520ffcbf0a/
      hvac/api/secrets_engines/transit.py#L274
- https://github.com/hvac/hvac/blob/b9343973307eaba1bbe28ebf9e1911520ffcbf0a/hvac/adapters.py#L94
- https://github.com/hvac/hvac/blob/b9343973307eaba1bbe28ebf9e1911520ffcbf0a/hvac/adapters.py#L287
"""

import base64
import hvac
import config
from hyok_logging import logger


def get_dynamic_secret(key: str, key_version: str, jwt_token: str) -> bytes:
    vault_url = config.get_config_by_key('VAULT_URL')
    client = hvac.Client(url=vault_url)

    logger.debug(f'Attempting to authenticate against Vault using JWT: {jwt_token}')

    response = client.auth.jwt.jwt_login(
        role=config.get_config_by_key('VAULT_JWT_DEFAULT_ROLE'),
        jwt=jwt_token)

    logger.debug(f'Vault login response: {response}')

    vault_token = response['auth']['client_token']

    if config.get_config_by_key('DEV_MODE'):
        logger.debug(f'Vault client token returned: {vault_token}')

    client = hvac.Client(url=vault_url, token=vault_token)

    if not client.sys.is_initialized():
        logger.error(f'Vault at "{vault_url}" has not been initialized.')
        return b''

    # fetch most recent key version of key
    response = client.secrets.transit.read_key(name=key)

    if key_version == 'latest':
        key_version = response['data']['latest_version']

    # fetch key
    response = client.secrets.transit.export_key(
        name=key, key_type='encryption-key', version=key_version)

    b64_key = response['data']['keys'][str(key_version)]

    return base64.b64decode(b64_key)
