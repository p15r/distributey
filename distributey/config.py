"""Reads JSON config file."""

# TODO: cache config in-mem instead of loading file every time.

import os
import json
import logging
from typing import Any
import inspect
import glom
from dy_trace import trace_enter, trace_exit

# dy_logging.logger() would cause import loop
logger = logging.getLogger(__name__)


def _is_cfg_path_valid(path: str) -> bool:
    """Validates format of config path supplied via env var."""
    trace_enter(inspect.currentframe())

    if not isinstance(path, str):
        logger.error('Config path is not a string.')
        ret = False
        trace_exit(inspect.currentframe(), ret)
        return ret

    max_path_length = 150
    if len(path) > max_path_length:
        logger.error('Config path is longer than %i chars.', max_path_length)
        ret = False
        trace_exit(inspect.currentframe(), ret)
        return ret

    parts = path.split('/')

    path_end = 'config.json'
    if parts[-1] != path_end:
        logger.error('Config path does not end with "%s"', path_end)
        ret = False
        trace_exit(inspect.currentframe(), ret)
        return ret

    ret = True
    trace_exit(inspect.currentframe(), ret)
    return ret


__CFG_PATH = os.getenv('DY_CFG_PATH', '')

if not _is_cfg_path_valid(__CFG_PATH):
    raise ValueError('Input validation for config path failed. Aborting...')


def get_config_by_keypath(keypath: str) -> Any:
    """Returns config by key path."""
    trace_enter(inspect.currentframe())

    try:
        with open(__CFG_PATH, 'r') as file:
            cfg = json.load(file)
    except FileNotFoundError as exc:
        ret = False
        logger.error('Config not found. Has "02-fix-cfg-perms.sh" '
                     'been executed? %s', exc)
        trace_exit(inspect.currentframe(), ret)
        return ret
    except Exception as exc:
        ret = False
        logger.error('Failed to load config: %s', exc)
        trace_exit(inspect.currentframe(), ret)
        return ret

    try:
        cfg_value = glom.glom(cfg, keypath)
    except glom.core.PathAccessError as exc:
        ret = False
        logger.error('Failed to load key "%s" from config: %s', keypath, exc)
        trace_exit(inspect.currentframe(), ret)
        return ret

    trace_exit(inspect.currentframe(), cfg_value)
    return cfg_value


def get_key_consumer_cert_by_tenant_and_kid(tenant: str, jwe_kid: str) -> str:
    """Returns key consumer certificate."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.backend.{jwe_kid}.key_consumer_cert'
    ret = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), ret)
    return ret


def get_vault_path_by_tenant_and_kid(tenant: str, jwe_kid: str) -> str:
    """Returns Vault path."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.backend.{jwe_kid}.vault_path'
    ret = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), ret)
    return ret


def get_jwt_algorithm_by_tenant(tenant: str) -> str:
    """Returns JWT algorithm."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.auth.jwt_algorithm'
    ret = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), ret)
    return ret


def get_jwt_audience_by_tenant(tenant: str) -> str:
    """Returns JWT audience claim."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.auth.jwt_audience'
    ret = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), ret)
    return ret


def get_jwt_subject_by_tenant(tenant: str) -> str:
    """Returns JWT sub claim."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.auth.jwt_subject'
    ret = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), ret)
    return ret


def get_jwt_issuer_by_tenant(tenant: str) -> str:
    """Returns JWT issuer claim."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.auth.jwt_issuer'
    ret = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), ret)
    return ret


def get_jwt_validation_cert_by_tenant_and_kid(
        tenant: str, jwt_kid: str) -> str:
    """Returns JWT validation certificate."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.auth.jwt_validation_certs.{jwt_kid}'
    ret = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), ret)
    return ret


def get_vault_default_role_by_tenant(tenant: str) -> str:
    """Returns Vault default role."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.vault_default_role'
    ret = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), ret)
    return ret


def get_vault_auth_jwt_path_by_tenant(tenant: str) -> str:
    """Returns Vault authorization JWT path."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.vault_auth_jwt_path'
    ret = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), ret)
    return ret


def get_vault_transit_path_by_tenant(tenant: str) -> str:
    """Returns Vault transit path."""
    trace_enter(inspect.currentframe())

    cfg_keypath = f'TENANT_CFG.{tenant}.vault_transit_path'
    ret = get_config_by_keypath(cfg_keypath)

    trace_exit(inspect.currentframe(), ret)
    return ret
