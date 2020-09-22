from markupsafe import escape
from flask import request
from flask import Flask
from flask import Response
import json
import jwt
from werkzeug.datastructures import EnvironHeaders
from os import getpid

import jwe
import config
from hyok_logging import logger

app = Flask(__name__)

logger.info(f'🚀 HYOK Wrapper is starting (pid {getpid()})...')

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
        logger.error(f'Cannot decode JWT in order to get kid: {e}')
        logger.debug(f'JWT: {token}')
        return ''

    return protected_header_unverified.get('kid', '')


def get_jwt_from_header(header: EnvironHeaders) -> str:
    try:
        token = header['Authorization']
    except KeyError:
        logger.error('Request is missing "Authorization" header. Cannot authorize request.')
        logger.debug(f'Malformed header: {header}')
        return ''

    # TODO: Is this always an OAuth Bearer Token (rfc6750)?
    if not token.startswith('Bearer'):
        logger.error('Cannot get Bearer token from Authorization header. Cannot authorize request.')
        logger.debug(f'Authorization header w/o Bearer: {token}')
        return ''

    token = token.split('Bearer')[1].strip()

    return token


def authenticate(tenant: str, header: EnvironHeaders) -> str:
    """
    Toke must..
    - have a valid signature,
    - contain 'sub': 'salesforce-cacheonlyservice',
    - not have been expired yet

    JWT signature verification might not be required, because this is done by Vault as well.
    However, it might be useful to implement a vault token<->jwt cache,
    which requires to authenticate in HYOK Wrapper too.
    """

    token = get_jwt_from_header(header)

    # TODO: walrus operator
    if not token:
        logger.error('Cannot get JWT from request.')
        logger.debug(f'Request header: {header}')
        return ''

    jwt_kid = get_kid_from_jwt(token)

    # TODO: walrus operator
    if not jwt_kid:
        logger.error('Cannot get kid from JWT.')
        logger.debug(f'JWT: {token}')
        return ''

    logger.info(f'Attempting to authenticate JWT with kid "{jwt_kid}"...')

    validation_cert = config.get_jwt_validation_certs_by_tenant_and_kid(tenant, jwt_kid)

    if not validation_cert:
        logger.error(
            f'No validation certificate exists in config.json '
            f'to verify signature for JWTs with kid "{jwt_kid}".')
        return ''

    # cert must be in PEM format, required by pyjwt[crypto] &
    # not the cert, only the public key.
    # Convert to PEM: openssl x509 -in mycert.crt -out mycert.pem -outform PEM
    # Extract public key from cert: openssl x509 -pubkey -noout -in cert.pem  > pubkey.pem
    # TODO: extract key from cert programmatically:
    #       https://pyjwt.readthedocs.io/en/latest/faq.html#how-can-i-extract-a-public-private-key-from-a-x509-certificate
    cert = open(validation_cert).read()

    if not cert:
        logger.error(
            f'Cannot read public key at "{cert}". Make sure its format is PEM.')
        return ''

    logger.debug(f'Received JWT: {token}')

    try:
        payload = jwt.decode(
            token, cert,
            audience=config.get_jwt_audience_by_tenant(tenant),
            algorithms=config.get_jwt_algorithm_by_tenant(tenant),
            options={
                'require_exp': True,
                'verify_signature': True,
                'verify_exp': True
                }
            )
    except jwt.InvalidSignatureError as e:
        logger.error(
            f'Unauthorized login attempt using invalid public key: {e}')
        return ''
    except jwt.ExpiredSignatureError as e:
        logger.error(
            f'Cannot authorize request, because the JWT has expired: {e}')
        return ''

    # Example JWT token payload:
    # {
    #     "iss": "salesforce",
    #     "sub": "salesforce-cacheonlyservice",
    #     "aud": "urn:hyok-wrapper",
    #     "nbf": 1598271437,
    #     "iat": 1598271437,
    #     "exp": 1598271737
    # }
    logger.debug(f'Payload of JWT with kid "{jwt_kid}": {payload}')

    if payload['sub'] == config.get_jwt_subject_by_tenant(tenant):
        logger.info(
            f'Successfully authenticated JWT with kid "{jwt_kid}".')
        return token
    else:
        logger.error(
            f'Cannot authorize JWT. Wrong subject "{payload["sub"]}".')
        return ''

    # TODO: check for issuer? (iss) as well?

    return ''


@app.route(path_prefix + '<string:tenant>/<string:jwe_kid>', methods=['GET'])
def get_jwe_token(tenant: str = '', jwe_kid: str = ''):
    """
    tenant: Tenant (key consumer) that makes a request. E.g. Salesforce. Mandatory.
    jwe_kid: kid provided by Salesforce. Mandatory.
    nonce: Nonce (?requestId=x) provided by Salesforce (prevent replay attacks). Optional.
    """
    token = authenticate(tenant, request.headers)

    if not token:
        return f'Unauthorized request from {request.headers["X-Real-Ip"]}, ({request.user_agent}).', 401

    request_args = []
    for key in request.args:
        request_args.append(f'{key}: {request.args.get(key)}')

    logger.info(f'Processing request (path: "{request.path}", args: "{request_args}"...')

    json_jwe_token = jwe.get_wrapped_key_as_jwe(
        token,
        str(escape(tenant)),
        str(escape(jwe_kid)),
        str(escape(request.args.get('requestId', ''))))

    if not json_jwe_token:
        return 'Oops, internal error.', 500

    logger.info(
        f'Response JWE token with kid "{json.loads(json_jwe_token)["kid"]}" sent.',)
    logger.debug(
        f'Reponse JWE token sent: {json_jwe_token}',)

    resp = Response(
        response=json_jwe_token,
        status=200,
        content_type='application/json; charset=utf-8')

    return resp
