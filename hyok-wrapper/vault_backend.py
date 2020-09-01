# This module implements communication with Hashicorp Vault.

import base64
import hvac
import config
import logging

def authenticate(jwt_token: str) -> str:
    logger = logging.getLogger(__name__)

    vault_url = config.get_config_by_key('VAULT_URL')
    client = hvac.Client(url=vault_url)

    response = client.auth.jwt.jwt_login(
        role = config.get_config_by_key('VAULT_JWT_DEFAULT_ROLE'),
        jwt = jwt_token
    )

    vault_token = response['auth']['client_token']
    logger.debug(f'Vault client token returned: {vault_token}')

    return vault_token

def get_dynamic_secret(key: str, vault_token: str) -> bytes:
    logger = logging.getLogger(__name__)

    vault_url = config.get_config_by_key('VAULT_URL')
    client = hvac.Client(url=vault_url, token=vault_token)

    if not client.sys.is_initialized():
        logger.error('Vault has not been initialized.')
        return b''

    # fetch latest version of key
    try:
        response = client.secrets.transit.read_key(name=key)
    except Exception as e:
        logger.error(f'Transit key "{key}" cannot be read.')
        logger.error(e)
        return b''

    try:
        latest_version = response['data']['latest_version']
    except KeyError as e:
        logger.error(f'Cannot get latest version of key "{key}":')
        logger.error(e)
        return b''

    # fetch key
    response = client.secrets.transit.export_key(
        name=key, key_type='encryption-key', version=latest_version)

    try:
        b64_key = response['data']['keys'][str(latest_version)]
    except KeyError as e:
        logger.error(f'Cannot get key "{key}":')
        logger.error(e)
        return b''

    return base64.b64decode(b64_key)
