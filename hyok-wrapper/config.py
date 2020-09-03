# Loads json config

import json
import logging
from typing import Any

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


def get_jwe_kid_to_vault_path_mapping(jwe_kid: str) -> str:
    jwe_map = get_config_by_key('JWE_KID_TO_VAULT_PATH_MAP')

    mapping = jwe_map.get(jwe_kid, '')

    return mapping
