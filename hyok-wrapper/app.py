from markupsafe import escape
from flask import request
from flask import Flask
import json
import logging
import sys
import jwt

import jwe
import vault_backend
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

def get_kid_from_jwt(token: str) -> str:
    # base64 decode token
    # token = json.loads(token)
    # return token['kid']
    return ''


@app.route(path_prefix + '/<string:kid>', methods=['GET'])
def get_jwe_token(kid: str = ''):
    """
    kid: kid provided by Salesforce. Mandatory.
    nonce: Nonce (?requestId=x) provided by Salesforce (prevent replay attacks). Optional.
    """

    x_real_ip = request.headers['X-Real-Ip']
    user_agent = request.user_agent
    origin_id = f'"{x_real_ip}" ({user_agent})'

    token = request.headers['Authorization']

    # TODO: Is this always an OAuth Bearer Token (rfc6750)?
    if not token.startswith('Bearer'):
        app.logger.error(
            f'Cannot get Bearer token from Authorization header. '
            f'Cannot authorize request from {origin_id}')
        app.logger.debug(f'Authorization header w/o Bearer: {token}')
        return False

    token = token.split('Bearer')[1].strip()

    app.logger.debug(f'Received JWT token: {token} from {origin_id}')

    vault_token = vault_backend.authenticate(token)


    request_args = []
    for key in request.args:
        request_args.append(f'{key}: {request.args.get(key)}')

    app.logger.info(
        f'Processing request from "{request.headers["X-Real-Ip"]}" ({request.user_agent})'
        f' path: "{request.path}".'
        f' args: {request_args}')

    json_jwe_token = jwe.get_wrapped_key_as_jwe(
        vault_token,
        kid=str(escape(kid)),
        nonce=str(escape(request.args.get('requestId', ''))))

    if not json_jwe_token:
        return 'Oops, internal error.', 500

    app.logger.debug(f'JWE token sent: {json_jwe_token}')
    app.logger.info(f'JWE token with kid "{json.loads(json_jwe_token)["kid"]}" sent in response.')

    return json_jwe_token
