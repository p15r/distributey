from markupsafe import escape
from flask import request
from flask import Flask
from flask import Response
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

# TODO move authenticate() and get_kid_from_jwt() to own module


def get_kid_from_jwt(token: str) -> str:
    # base64 decode token
    # token = json.loads(token)
    # return token['kid']

    try:
        protected_header_unverified = jwt.get_unverified_header(token)
    except jwt.DecodeError as e:
        app.logger.error(f'Cannot decode JWT to get kid: {e}')
        app.logger.debug(f'JWT: {token}')
        return ''

    return protected_header_unverified.get('kid', '')


def get_jwt_from_header(header: EnvironHeaders, origin_id: str) -> str:
    token = header['Authorization']

    # TODO: Is this always an OAuth Bearer Token (rfc6750)?
    if not token.startswith('Bearer'):
        app.logger.error(
            f'Cannot get Bearer token from Authorization header. '
            f'Cannot authorize request from {origin_id}')
        app.logger.debug(f'Authorization header w/o Bearer: {token}')
        return ''

    token = token.split('Bearer')[1].strip()

    return token


def authenticate(header: EnvironHeaders) -> str:
    """
    Toke must..
    - have a valid signature,
    - contain 'sub': 'salesforce-cacheonlyservice',
    - not have been expired yet

    JWT signature verification might not be required, because this is done by Vault as well.
    However, it might be useful to implement a vault token<->jwt cache,
    which requires to authenticate in HYOK Wrapper too.
    """
    x_real_ip = request.headers['X-Real-Ip']
    user_agent = request.user_agent
    origin_id = f'"{x_real_ip}" ({user_agent})'

    # get validation cert from: JWT_VALIDATION_CERTS
    validation_certs = config.get_config_by_key('JWT_VALIDATION_CERTS')

    token = get_jwt_from_header(header, origin_id)

    # something like:
    kid = get_kid_from_jwt(token)
    pubkey = validation_certs.get(kid, '')

    if not pubkey:
        app.logger.error(f'Cannot find pubkey in config.json to verify JWT signature for JWTs with kid "{kid}".')
        return ''

    # cert must be in PEM format, required by pyjwt[crypto] &
    # not the cert, only the public key.
    # Convert to PEM: openssl x509 -in mycert.crt -out mycert.pem -outform PEM
    # Extract public key from cert: openssl x509 -pubkey -noout -in cert.pem  > pubkey.pem
    # TODO: extract key from cert programmatically:
    #       https://pyjwt.readthedocs.io/en/latest/faq.html#how-can-i-extract-a-public-private-key-from-a-x509-certificate
    cert = open(pubkey).read()

    if not cert:
        app.logger.error(f'Cannot read public key at "{cert}". Make sure its format is PEM.')
        return ''

    app.logger.debug(f'Received JWT token: {token} from {origin_id}')

    try:
        payload = jwt.decode(
            token, cert,
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
            f'Unauthorized login attempt from {origin_id} using invalid public key: {e}')
        return ''
    except jwt.ExpiredSignatureError as e:
        app.logger.error(
            f'Cannot authorize request from {origin_id}, because the JWT has expired: {e}')
        return ''

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
            f'Successfully authenticated JWT from {origin_id}.')
        return token
    else:
        app.logger.error(f'Cannot authorize token from {origin_id}. Wrong subject "{payload["sub"]}".')
        return ''

    # TODO: check for issuer? (iss) as well?

    return ''


@app.route(path_prefix + 'sfhyok/<string:kid>', methods=['GET'])
def get_jwe_token(kid: str = ''):
    """
    kid: kid provided by Salesforce. Mandatory.
    nonce: Nonce (?requestId=x) provided by Salesforce (prevent replay attacks). Optional.
    """

    token = authenticate(request.headers)

    if not token:
        return 'Unauthorized request.', 401

    request_args = []
    for key in request.args:
        request_args.append(f'{key}: {request.args.get(key)}')

    app.logger.info(
        f'Processing request from "{request.headers["X-Real-Ip"]}" ({request.user_agent})'
        f' path: "{request.path}".'
        f' args: {request_args}')

    json_jwe_token = jwe.get_wrapped_key_as_jwe(
        token,
        str(escape(kid)),
        str(escape(request.args.get('requestId', ''))))

    if not json_jwe_token:
        return 'Oops, internal error.', 500

    app.logger.info(f'Response JWE token with kid "{json.loads(json_jwe_token)["kid"]}" sent.')
    app.logger.debug(f'Reponse JWE token sent: {json_jwe_token}')

    resp = Response(
        response=json_jwe_token,
        status=200,
        mimetype='application/json')

    return resp
