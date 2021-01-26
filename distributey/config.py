# TODO: Rewrite using (json) query approach: https://github.com/mwilliamson/jq.py

import json
import logging
from typing import Any
import inspect
from trace import trace_enter, trace_exit

# dy_logging.logger() would cause import loop
logger = logging.getLogger(__name__)

CFG_PATH = '/opt/distributey/config/config.json'


# TODO: be more specific than "Any" type hint.
def get_config_by_key(key: str) -> Any:
    trace_enter(inspect.currentframe())
    try:
        with open(CFG_PATH, 'r') as f:
            cfg = json.load(f)
    except FileNotFoundError as e:
        logger.error('Cannot load config file. Has "02-load-config.sh" already been executed?')
        logger.error(e)
        trace_exit(inspect.currentframe(), False)
        return False

    # Let this raise Exception if key does not exist
    trace_exit(inspect.currentframe(), cfg[key])
    return cfg[key]


def get_key_consumer_cert_by_tenant_and_kid(tenant: str, jwe_kid: str) -> str:
    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key('TENANT_CFG')[tenant]['backend'][jwe_kid]['key_consumer_cert']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as e:
        logger.error(
            f'Cannot access config (config/config.json) "{e}" '
            f'in path TENANT_CFG.{tenant}.backend.{jwe_kid}.key_consumer_cert')
        trace_exit(inspect.currentframe(), '')
        return ''


def get_vault_path_by_tenant_and_kid(tenant: str, jwe_kid: str) -> str:
    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key('TENANT_CFG')[tenant]['backend'][jwe_kid]['vault_path']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as e:
        logger.error(
            f'Cannot access config (config/config.json) "{e}" in path TENANT_CFG.{tenant}.backend.{jwe_kid}.vault_path')
        return ''


def get_jwt_algorithm_by_tenant(tenant: str) -> str:
    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key('TENANT_CFG')[tenant]['auth']['jwt_algorithm']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as e:
        logger.error(
            f'Cannot access config (config/config.json) "{e}" in path TENANT_CFG.{tenant}.auth.jwt_algorithm')
        trace_exit(inspect.currentframe(), '')
        return ''


def get_jwt_audience_by_tenant(tenant: str) -> str:
    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key('TENANT_CFG')[tenant]['auth']['jwt_audience']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as e:
        logger.error(
            f'Cannot access config (config/config.json) "{e}" in path TENANT_CFG.{tenant}.auth.jwt_audience')
        trace_exit(inspect.currentframe(), '')
        return ''


def get_jwt_subject_by_tenant(tenant: str) -> str:
    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key('TENANT_CFG')[tenant]['auth']['jwt_subject']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as e:
        logger.error(
            f'Cannot access config (config/config.json) "{e}" in path TENANT_CFG.{tenant}.auth.jwt_subject')
        trace_exit(inspect.currentframe(), '')
        return ''


def get_jwt_issuer_by_tenant(tenant: str) -> str:
    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key('TENANT_CFG')[tenant]['auth']['jwt_issuer']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as e:
        logger.error(
                f'Cannot access config (config/config.json) "{e}" in path TENANT_CFG.{tenant}.auth.jwt_issuer')
        trace_exit(inspect.currentframe(), '')
        return ''


def get_jwt_validation_cert_by_tenant_and_kid(tenant: str, jwt_kid: str) -> str:
    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key('TENANT_CFG')[tenant]['auth']['jwt_validation_certs'][jwt_kid]
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as e:
        logger.error(
            f'Cannot access config (config/config.json) "{e}" in path '
            f'TENANT_CFG.{tenant}.auth.jwt_validation_certs.{jwt_kid}')
        trace_exit(inspect.currentframe(), '')
        return ''


def get_vault_default_role_by_tenant(tenant: str) -> str:
    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key('TENANT_CFG')[tenant]['vault_default_role']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as e:
        logger.error(
            f'Cannot access config (config/config.json) "{e}" in path TENANT_CFG.{tenant}.vault_default_role')
        trace_exit(inspect.currentframe(), '')
        return ''


def get_vault_auth_jwt_path_by_tenant(tenant: str) -> str:
    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key('TENANT_CFG')[tenant]['vault_auth_jwt_path']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as e:
        logger.error(
            f'Cannot access config (config/config.json) "{e}" in path TENANT_CFG.{tenant}.vault_auth_jwt_path')
        trace_exit(inspect.currentframe(), '')
        return ''


def get_vault_transit_path_by_tenant(tenant: str) -> str:
    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key('TENANT_CFG')[tenant]['vault_transit_path']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as e:
        logger.error(
            f'Cannot access config (config/config.json) "{e}" in path TENANT_CFG.{tenant}.vault_transit_path')
        trace_exit(inspect.currentframe(), '')
        return ''
