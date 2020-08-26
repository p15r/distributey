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
    Toke must..
    - have a valid signature,
    - contain 'sub': 'salesforce-cacheonlyservice',
    - not have been expired yet
    """
    x_real_ip = request.headers['X-Real-Ip']
    user_agent = request.user_agent
    origin_id = f'"{x_real_ip}" ({user_agent})'

    validation_cert = config.get_config_by_key('JWT_VALIDATION_CERT')

    # cert must be in PEM format, required by pyjwt[crypto] &
    # not the cert, only the public key.
    # Convert to PEM: openssl x509 -in mycert.crt -out mycert.pem -outform PEM
    # Extract public key from cert: openssl x509 -pubkey -noout -in cert.pem  > pubkey.pem
    public_key = open(validation_cert).read()

    if not public_key:
        app.logger.error(f'Cannot read public key at "{validation_cert}". Make sure its format is PEM.')
        return False

    token = header['Authorization']

    # TODO: Is this always an OAuth Bearer Token (rfc6750)?
    if not token.startswith('Bearer'):
        app.logger.error(
            f'Cannot get Bearer token from Authorization header. '
            f'Cannot authorize request from {origin_id}')
        app.logger.debug(f'Authorization header w/o Bearer: {token}')
        return False

    token = token.split('Bearer')[1].strip()

    app.logger.debug(f'Received JWT token: {token} from {origin_id}')

    try:
        payload = jwt.decode(
            token, public_key,
            audience=config.get_config_by_key('JWT_AUDIENCE'),
            algorithms=config.get_config_by_key('JWT_ALGORITHMS'),
            options={
                'require_exp': True,
                'verify_signature': True,
                'verify_exp': True
                }
            )
    except jwt.InvalidSignatureError as e:
        app.logger.error(
            f'Unauthorized login attempt from {origin_id} using invalid certificate: {e}')
        return False
    except jwt.ExpiredSignatureError as e:
        app.logger.error(
            f'Cannot authorize request from {origin_id}, because token has expired: {e}')
        return False

    # Example JWT token payload:
    # {
    #     "iss": "myCA",
    #     "sub": "salesforce-cacheonlyservice",
    #     "aud": "urn:hyok-wrapper",
    #     "nbf": 1598271437,
    #     "iat": 1598271437,
    #     "exp": 1598271737
    # }
    app.logger.debug(f'Payload of JWT token: {payload}')

    if payload['sub'] == config.get_config_by_key('JWT_SUBJECT'):
        app.logger.info(
            f'Successfully authenticated token from {origin_id}.')
        return True
    else:
        app.logger.error(f'Cannot authorize token from {origin_id}. Wrong subject "{payload["sub"]}".')
        return False

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
