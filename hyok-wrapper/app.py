from markupsafe import escape
from flask import request
from flask import Flask
import json
import logging
import sys
import jwt
from werkzeug.datastructures import EnvironHeaders

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


def is_authenticated(header: EnvironHeaders) -> bool:
    """
    If token has a valid signature and contains 'sub': 'salesforce-cacheonlyservice',
    it is granted access.
    """
    # TODO: str is a class from flask.request.header. Improve type hinting.
    validation_cert = config.get_config_by_key('JWT_VALIDATION_CERT')

    # cert must be in PEM format, otherwise error msg: "Could not deserialize key data"
    public_key = open(validation_cert).read()

    # TODO: check if public_key is empty or not

    token = header['Authorization']

    # TODO: is there a scenarion where there is no Bearer?
    if token.startswith('Bearer'):
        token = token.split('Bearer')[1].strip()

    try:
        # TODO: this only allows to verify sign of specific cert. It is not possible to verify sign using CA cert. Why?
        payload = jwt.decode(
            token, public_key,
            audience=['urn:hyok-wrapper'],
            algorithms=['RS256'],
            options={'verify_signature': True})
    except jwt.exceptions.InvalidSignatureError as e:
        app.logger.error(
            f'Unauthorized login attempt using invalid certificate: {e}'
            f' (source IP address "{request.headers["X-Real-Ip"]}" [{request.user_agent}])')
        return False

    # Example payload:
    # {'iss': 'myCA', 'sub': 'salesforce-cacheonlyservice', 'aud': 'urn:hyok-wrapper',
    #   'nbf': 1598271437, 'iat': 1598271437, 'exp': 1598271737}
    app.logger.debug(f'payload: {payload}')

    if payload['sub'] == 'salesforce-cacheonlyservice':
        app.logger.info(
            f'Successfully authenticated token from {request.headers["X-Real-Ip"]} ({request.user_agent}).')
        return True

    return False


@app.route(path_prefix + '/<string:kid>', methods=['GET'])
def get_jwe_token(kid: str = ''):
    """
    kid: kid provided by Salesforce. Mandatory.
    nonce: Nonce (?requestId=x) provided by Salesforce (prevent replay attacks). Optional.
    """

    if not is_authenticated(request.headers):
        return 'Unauthorized request.', 401

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
