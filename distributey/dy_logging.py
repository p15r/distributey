import logging
import sys
from flask import request, has_request_context
import config


log_level = config.get_config_by_key('LOG_LEVEL')

if log_level == 'debug':
    loglvl = logging.DEBUG
else:
    loglvl = logging.INFO


class __RequestFormatter(logging.Formatter):
    def format(self, record):
        if has_request_context():
            # request.path.split() is safe, because URL is validated by Flask on entry.
            record.tenant = request.path.split('/')[2]
            record.x_real_ip = request.headers['X-Real-Ip']
            record.user_agent = request.user_agent
        else:
            record.tenant = 'system'
            record.x_real_ip = 'localhost'
            record.user_agent = 'n/a'

        return super().format(record)


__stream_handler = logging.StreamHandler(stream=sys.stderr)
__stream_handler.setFormatter(
    __RequestFormatter(
        '[%(asctime)s] distributey {%(pathname)s:%(lineno)d} %(levelname)s - '
        'tenant: %(tenant)s, origin: %(x_real_ip)s, ua: %(user_agent)s - %(message)s'))

logger = logging.getLogger()
logger.setLevel(loglvl)
logger.addHandler(__stream_handler)
