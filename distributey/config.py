# TODO: Rewrite using (json) query approach: https://github.com/mwilliamson/jq.py

import json
import logging
from typing import Any

# distributey_logging.logger() would cause import loop
logger = logging.getLogger(__name__)

CFG_PATH = '/opt/distributey/config/config.json'


# TODO: be more specific than "Any" type hint.
def get_config_by_key(key: str) -> Any:
    try:
        with open(CFG_PATH, 'r') as f:
            cfg = json.load(f)
    except FileNotFoundError as e:
        logger.error('Cannot load config file. Has "02-load-config.sh" already been executed?')
        logger.error(e)
        return False

    # Let this raise KeyError if key does not exist
    return cfg[key]


def get_key_consumer_cert_by_tenant_and_kid(tenant: str, jwe_kid: str) -> str:
    try:
        return get_config_by_key('TENANT_CFG')[tenant]['backend'][jwe_kid]['key_consumer_cert']
    except KeyError as e:
        logger.error(
            f'Cannot access config (config/config.json) "{e}" '
            f'in path TENANT_CFG.{tenant}.backend.{jwe_kid}.key_consumer_cert')
        return ''


def get_vault_path_by_tenant_and_kid(tenant: str, jwe_kid: str) -> str:
    try:
        return get_config_by_key('TENANT_CFG')[tenant]['backend'][jwe_kid]['vault_path']
    except KeyError as e:
        logger.error(
            f'Cannot access config (config/config.json) "{e}" in path TENANT_CFG.{tenant}.backend.{jwe_kid}.vault_path')
        return ''


def get_jwt_algorithm_by_tenant(tenant: str) -> str:
    try:
        return get_config_by_key('TENANT_CFG')[tenant]['auth']['jwt_algorithm']
    except KeyError as e:
        logger.error(
            f'Cannot access config (config/config.json) "{e}" in path TENANT_CFG.{tenant}.auth.jwt_algorithm')
        return ''


def get_jwt_audience_by_tenant(tenant: str) -> str:
    try:
        return get_config_by_key('TENANT_CFG')[tenant]['auth']['jwt_audience']
    except KeyError as e:
        logger.error(
            f'Cannot access config (config/config.json) "{e}" in path TENANT_CFG.{tenant}.auth.jwt_audience')
        return ''


def get_jwt_subject_by_tenant(tenant: str) -> str:
    try:
        return get_config_by_key('TENANT_CFG')[tenant]['auth']['jwt_subject']
    except KeyError as e:
        logger.error(
            f'Cannot access config (config/config.json) "{e}" in path TENANT_CFG.{tenant}.auth.jwt_subject')
        return ''


def get_jwt_issuer_by_tenant(tenant: str) -> str:
    try:
        return get_config_by_key('TENANT_CFG')[tenant]['auth']['jwt_issuer']
    except KeyError as e:
        logger.error(
                f'Cannot access config (config/config.json) "{e}" in path TENANT_CFG.{tenant}.auth.jwt_issuer')
        return ''


def get_jwt_validation_cert_by_tenant_and_kid(tenant: str, jwt_kid: str) -> str:
    try:
        return get_config_by_key('TENANT_CFG')[tenant]['auth']['jwt_validation_certs'][jwt_kid]
    except KeyError as e:
        logger.error(
            f'Cannot access config (config/config.json) "{e}" in path '
            f'TENANT_CFG.{tenant}.auth.jwt_validation_certs.{jwt_kid}')
        return ''


def get_vault_default_role_by_tenant(tenant: str) -> str:
    try:
        return get_config_by_key('TENANT_CFG')[tenant]['vault_default_role']
    except KeyError as e:
        logger.error(
            f'Cannot access config (config/config.json) "{e}" in path TENANT_CFG.{tenant}.vault_default_role')
        return ''


def get_vault_auth_jwt_path_by_tenant(tenant: str) -> str:
    try:
        return get_config_by_key('TENANT_CFG')[tenant]['vault_auth_jwt_path']
    except KeyError as e:
        logger.error(
            f'Cannot access config (config/config.json) "{e}" in path TENANT_CFG.{tenant}.vault_auth_jwt_path')
        return ''


