from markupsafe import escape
from flask import request
from flask import Flask
import json
import logging
import sys

import jwe
import config


log_level = config.get_config_by_key('LOG_LEVEL')

if log_level == 'debug':
    loglvl = logging.DEBUG
else:
    loglvl = logging.INFO

logging.basicConfig(
    stream=sys.stderr,
    level=loglvl,
    format='[%(asctime)s] HYOK {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s')

app = Flask(__name__)

# URL-based API versioning
root_path = '/'
api_versioning_path = 'v1/'
path_prefix = root_path + api_versioning_path


@app.route(path_prefix + '/<string:kid>', methods=['GET'])
def get_jwe_token(kid: str = ''):
    """
    kid: kid provided by Salesforce. Mandatory.
    nonce: Nonce (?requestId=x) provided by Salesforce (prevent replay attacks). Optional.
    """

    request_args = []
    for key in request.args:
        request_args.append(f'{key}: {request.args.get(key)}')

    app.logger.info(
        f'Processing request from "{request.headers["X-Real-Ip"]}" ({request.user_agent})'
        f' path: "{request.path}".'
        f' args: {request_args}')

    json_jwe_token = jwe.get_wrapped_key_as_jwe(
        kid=str(escape(kid)),
        nonce=str(escape(request.args.get('requestId', ''))))

    if not json_jwe_token:
        return 'Oops, internal error.', 500

    app.logger.debug(f'JWE token sent: {json_jwe_token}')
    app.logger.info(f'JWE token with kid "{json.loads(json_jwe_token)["kid"]}" sent in response.')

    return json_jwe_token
