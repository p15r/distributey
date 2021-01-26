"""Makes config file (json-based) accessible for distributey."""

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
    """Returns config."""

    trace_enter(inspect.currentframe())
    try:
        with open(CFG_PATH, 'r') as file:
            cfg = json.load(file)
    except FileNotFoundError as exc:
        logger.error('Cannot load config file. Has "02-load-config.sh" '
                     'already been executed? %s', exc)
        trace_exit(inspect.currentframe(), False)
        return False

    # Let this raise Exception if key does not exist
    trace_exit(inspect.currentframe(), cfg[key])
    return cfg[key]


def get_key_consumer_cert_by_tenant_and_kid(tenant: str, jwe_kid: str) -> str:
    """Returns key consumer certificate."""

    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key(
            'TENANT_CFG')[tenant]['backend'][jwe_kid]['key_consumer_cert']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as exc:
        logger.error('Cannot access config (config/config.json) "%s" in '
                     'path TENANT_CFG.%s.backend.%s.'
                     'key_consumer_cert', exc, tenant, jwe_kid)
        trace_exit(inspect.currentframe(), '')
        return ''


def get_vault_path_by_tenant_and_kid(tenant: str, jwe_kid: str) -> str:
    """Returns Vault path."""

    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key(
            'TENANT_CFG')[tenant]['backend'][jwe_kid]['vault_path']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as exc:
        logger.error('Cannot access config (config/config.json) "%s" in '
                     'path TENANT_CFG.%s.backend.%s.vault_path',
                     exc, tenant, jwe_kid)
        return ''


def get_jwt_algorithm_by_tenant(tenant: str) -> str:
    """Returns JWT algorithm."""

    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key('TENANT_CFG')[tenant]['auth']['jwt_algorithm']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as exc:
        logger.error('Cannot access config (config/config.json) "%s" in '
                     'path TENANT_CFG.%s.auth.jwt_algorithm', exc, tenant)
        trace_exit(inspect.currentframe(), '')
        return ''


def get_jwt_audience_by_tenant(tenant: str) -> str:
    """Returns JWT audience claim."""

    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key('TENANT_CFG')[tenant]['auth']['jwt_audience']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as exc:
        logger.error('Cannot access config (config/config.json) "%s" in '
                     'path TENANT_CFG.%s.auth.jwt_audience', exc, tenant)
        trace_exit(inspect.currentframe(), '')
        return ''


def get_jwt_subject_by_tenant(tenant: str) -> str:
    """Returns JWT sub claim."""

    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key('TENANT_CFG')[tenant]['auth']['jwt_subject']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as exc:
        logger.error(
            'Cannot access config (config/config.json) "%s" in path '
            'TENANT_CFG.%s.auth.jwt_subject', exc, tenant)
        trace_exit(inspect.currentframe(), '')
        return ''


def get_jwt_issuer_by_tenant(tenant: str) -> str:
    """Returns JWT issuer claim."""

    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key('TENANT_CFG')[tenant]['auth']['jwt_issuer']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as exc:
        logger.error('Cannot access config (config/config.json) "%s" in '
                     'path TENANT_CFG.%s.auth.jwt_issuer', exc, tenant)
        trace_exit(inspect.currentframe(), '')
        return ''


def get_jwt_validation_cert_by_tenant_and_kid(
        tenant: str, jwt_kid: str) -> str:
    """Returns JWT validation certificate."""

    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key(
            'TENANT_CFG')[tenant]['auth']['jwt_validation_certs'][jwt_kid]
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as exc:
        logger.error('Cannot access config (config/config.json) "%s" in '
                     'path TENANT_CFG.%s.auth.'
                     'jwt_validation_certs.%s', exc, tenant, jwt_kid)
        trace_exit(inspect.currentframe(), '')
        return ''


def get_vault_default_role_by_tenant(tenant: str) -> str:
    """Returns Vault default role."""

    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key('TENANT_CFG')[tenant]['vault_default_role']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as exc:
        logger.error('Cannot access config (config/config.json) "%s" in '
                     'path TENANT_CFG.%s.vault_default_role', exc, tenant)
        trace_exit(inspect.currentframe(), '')
        return ''


def get_vault_auth_jwt_path_by_tenant(tenant: str) -> str:
    """Returns Vault authorization JWT path."""

    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key('TENANT_CFG')[tenant]['vault_auth_jwt_path']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as exc:
        logger.error('Cannot access config (config/config.json) "%s" in '
                     'path TENANT_CFG.%s.vault_auth_jwt_path', exc, tenant)
        trace_exit(inspect.currentframe(), '')
        return ''


def get_vault_transit_path_by_tenant(tenant: str) -> str:
    """Returns Vault transit path."""

    trace_enter(inspect.currentframe())
    try:
        ret = get_config_by_key('TENANT_CFG')[tenant]['vault_transit_path']
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as exc:
        logger.error('Cannot access config (config/config.json) "%s" in '
                     'path TENANT_CFG.%s.vault_transit_path', exc, tenant)
        trace_exit(inspect.currentframe(), '')
        return ''
