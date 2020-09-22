"""
Loads JSON-based config.

TODO:
- rewrite using (json) query approach: https://github.com/mwilliamson/jq.py
"""

import json
import logging
from typing import Any

# do not use logger.get_loger(), because that would create import loop
logger = logging.getLogger(__name__)


def get_config_by_key(key: str) -> Any:
    # Todo:
    #  - more precise typing for key: Union[str, list, dict, int]

    try:
        with open('/opt/hyok-wrapper/config/config.json', 'r') as f:
            cfg = json.load(f)
    except FileNotFoundError as e:
        logger.error('Cannot load config file. Has "02-load-config.sh" already been executed?')
        logger.error(e)
        return {}

    # Let this raise KeyError if key does not exist
    return cfg[key]


def get_key_consumer_cert_by_tenant_and_kid(tenant: str, jwe_kid: str) -> str:
    try:
        return get_config_by_key('TENANT_CFG')[tenant]['backend'][jwe_kid]['key_consumer_cert']
    except KeyError as e:
        logger.error(
            f'Cannot access config (config/config.json) {e} '
            f'in path TENANT_CFG.{tenant}.backend.{jwe_kid}.key_consumer_cert')
        raise e


def get_vault_path_by_tenant_and_kid(tenant: str, jwe_kid: str) -> str:
    try:
        return get_config_by_key('TENANT_CFG')[tenant]['backend'][jwe_kid]['vault_path']
    except KeyError as e:
        logger.error(
            f'Cannot access config (config/config.json) {e} in path TENANT_CFG.{tenant}.backend.{jwe_kid}.vault_path')
        raise e


def get_jwt_algorithm_by_tenant(tenant: str) -> str:
    try:
        return get_config_by_key('TENANT_CFG')[tenant]['auth']['jwt_algorithm']
    except KeyError as e:
        logger.error(
            f'Cannot access config (config/config.json) {e} in path TENANT_CFG.{tenant}.auth.jwt_algorithm')
        raise e


def get_jwt_audience_by_tenant(tenant: str) -> str:
    try:
        return get_config_by_key('TENANT_CFG')[tenant]['auth']['jwt_audience']
    except KeyError as e:
        logger.error(
            f'Cannot access config (config/config.json) {e} in path TENANT_CFG.{tenant}.auth.jwt_audience')
        raise e


def get_jwt_subject_by_tenant(tenant: str) -> str:
    try:
        return get_config_by_key('TENANT_CFG').get(tenant).get('auth').get('jwt_subject')
    except KeyError as e:
        logger.error(
            f'Cannot access config (config/config.json) {e} in path TENANT_CFG.{tenant}.auth.jwt_subject')
        raise e


def get_jwt_validation_certs_by_tenant_and_kid(tenant: str, jwt_kid: str) -> str:
    try:
        return get_config_by_key('TENANT_CFG')[tenant]['auth']['jwt_validation_certs'][jwt_kid]
    except KeyError as e:
        logger.error(
            f'Cannot access config (config/config.json) {e} in path TENANT_CFG.{tenant}.auth.jwt_validation_certs')
        raise e
