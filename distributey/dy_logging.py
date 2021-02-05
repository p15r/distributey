"""Provides formatted logging handler for distributey."""

import logging
import sys
from flask import has_request_context, session
import config


log_level = config.get_config_by_keypath('LOG_LEVEL')
splunk_enabled = config.get_config_by_keypath('SPLUNK_ENABLED')

if log_level == 'debug':
    LOGLVL = logging.DEBUG
else:
    LOGLVL = logging.INFO


class __RequestFormatter(logging.Formatter):
    def format(self, record):
        if has_request_context():
            try:
                record.user_agent = session['header_args']['user-agent']
                record.tenant = session['view_args']['tenant']
                record.x_real_ip = session['header_args']['x-real-ip']
            except KeyError:
                # input validation failed
                record.user_agent = 'N/A'
                record.tenant = 'N/A'
                record.x_real_ip = 'N/A'
        else:
            record.tenant = 'system'
            record.x_real_ip = 'localhost'
            record.user_agent = 'n/a'

        return super().format(record)


__stream_handler = logging.StreamHandler(stream=sys.stderr)
__stream_handler.setFormatter(
    __RequestFormatter(
        '[%(asctime)s] distributey {%(pathname)s:%(lineno)d} %(levelname)s - '
        'tenant: %(tenant)s, origin: %(x_real_ip)s, '
        'ua: %(user_agent)s - %(message)s'))

logger = logging.getLogger()
logger.setLevel(LOGLVL)
logger.addHandler(__stream_handler)

if splunk_enabled:
    from splunk_handler import SplunkHandler

    __splunk = SplunkHandler(
        host=config.get_config_by_keypath('SPLUNK_HOST'),
        port=config.get_config_by_keypath('SPLUNK_PORT'),
        protocol=config.get_config_by_keypath('SPLUNK_PROTOCOL'),
        verify=config.get_config_by_keypath('SPLUNK_VERIFY'),
        token=config.get_config_by_keypath('SPLUNK_TOKEN'),
        index=config.get_config_by_keypath('SPLUNK_INDEX'))

    logger.addHandler(__splunk)
