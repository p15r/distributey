"""Makes config file (json-based) accessible for distributey."""

# TODO: cache config in-mem instead of loading file every time.

import json
import logging
from typing import Any
import inspect
import glom
from dy_trace import trace_enter, trace_exit

# dy_logging.logger() would cause import loop
logger = logging.getLogger(__name__)

CFG_PATH = '/opt/distributey/config/config.json'


# TODO: be more specific than "Any" type hint.
def get_config_by_keypath(keypath: str) -> Any:
    """Returns config."""

    trace_enter(inspect.currentframe())
    try:
        with open(CFG_PATH, 'r') as file:
            cfg = json.load(file)
    except FileNotFoundError as exc:
        logger.error('Config not found. Has "02-fix-cfg-perms.sh" '
                     'been executed? %s', exc)
        trace_exit(inspect.currentframe(), False)
        return False
    except Exception as exc:
        logger.error('Failed to load config: %s', exc)
        trace_exit(inspect.currentframe(), False)
        return False

    try:
        cfg_value = glom.glom(cfg, keypath)
    except glom.core.PathAccessError as exc:
        ret = ''
        logger.error('Failed to load key "%s" from config: %s', keypath, exc)
        trace_exit(inspect.currentframe(), ret)
        return ret

    trace_exit(inspect.currentframe(), cfg_value)
    return cfg_value


def get_key_consumer_cert_by_tenant_and_kid(tenant: str, jwe_kid: str) -> str:
    """Returns key consumer certificate."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.backend.{jwe_kid}.key_consumer_cert'
    cfg_value = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), cfg_value)
    return cfg_value


def get_vault_path_by_tenant_and_kid(tenant: str, jwe_kid: str) -> str:
    """Returns Vault path."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.backend.{jwe_kid}.vault_path'
    cfg_value = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), cfg_value)
    return cfg_value


def get_jwt_algorithm_by_tenant(tenant: str) -> str:
    """Returns JWT algorithm."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.auth.jwt_algorithm'
    cfg_value = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), cfg_value)
    return cfg_value


def get_jwt_audience_by_tenant(tenant: str) -> str:
    """Returns JWT audience claim."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.auth.jwt_audience'
    cfg_value = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), cfg_value)
    return cfg_value


def get_jwt_subject_by_tenant(tenant: str) -> str:
    """Returns JWT sub claim."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.auth.jwt_subject'
    cfg_value = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), cfg_value)
    return cfg_value


def get_jwt_issuer_by_tenant(tenant: str) -> str:
    """Returns JWT issuer claim."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.auth.jwt_issuer'
    cfg_value = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), cfg_value)
    return cfg_value


def get_jwt_validation_cert_by_tenant_and_kid(
        tenant: str, jwt_kid: str) -> str:
    """Returns JWT validation certificate."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.auth.jwt_validation_certs.{jwt_kid}'
    cfg_value = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), cfg_value)
    return cfg_value


def get_vault_default_role_by_tenant(tenant: str) -> str:
    """Returns Vault default role."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.vault_default_role'
    cfg_value = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), cfg_value)
    return cfg_value


def get_vault_auth_jwt_path_by_tenant(tenant: str) -> str:
    """Returns Vault authorization JWT path."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.vault_auth_jwt_path'
    cfg_value = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), cfg_value)
    return cfg_value


def get_vault_transit_path_by_tenant(tenant: str) -> str:
    """Returns Vault transit path."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.vault_transit_path'
    cfg_value = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), cfg_value)
    return cfg_value
