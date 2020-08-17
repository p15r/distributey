# Loads json config

import json


def get_config(key: str) -> str:
    try:
        with open('/opt/hyok-wrapper/config/config.json', 'r') as f:
            cfg = json.load(f)
    except FileNotFoundError as e:
        print('Cannot load config file. Has "02-load-config.sh" already been executed?')
        print(e)
        return ''

    # Let this raise KeyError if key does not exist
    return cfg[key]
