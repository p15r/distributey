from markupsafe import escape
from flask import request
from flask import Flask
from flask import Response
import json
import jwt
from werkzeug.datastructures import EnvironHeaders
from os import getpid
from typing import Tuple

import jwe
import config
from hyok_logging import logger


app = Flask(__name__)

logger.info(f'🚀 HYOK Wrapper is starting (pid {getpid()})...')

# URL-based API versioning
base_path = '/'
api_versioning_path = 'v1/'
path_prefix = base_path + api_versioning_path


def _get_kid_from_jwt(token: str) -> str:
    try:
        protected_header_unverified = jwt.get_unverified_header(token)
    except jwt.DecodeError as e:
        logger.error(f'Cannot decode JWT in order to get kid: {e}')
        logger.debug(f'JWT: {token}')
        return ''

    return protected_header_unverified.get('kid', '')


def _get_jwt_from_header(header: EnvironHeaders) -> str:
    try:
        token = header['Authorization']
    except KeyError:
        logger.error('Request is missing "Authorization" header.')
        logger.debug(f'Malformed header: {header}')
        return ''

    if not token.startswith('Bearer'):
        logger.error('Cannot fetch Bearer token from Authorization header.')
        logger.debug(f'Malformed token w/o Bearer: {token}')
        return ''

    token = token.split('Bearer')[1].strip()

    return token


def _decode_jwt(tenant: str, jwt_token: str, cert: str) -> Tuple[str, str]:
    """
    The jwt_token must..
    - have a valid signature,
    - contain 'iss' & 'sub' claims
    - not have expired (leeway of 10s for clock skew is tolerated)
    """

    if not (aud := config.get_jwt_audience_by_tenant(tenant)):
        raise Exception(f'Cannot get JWT audience for tenant "{tenant}" from config.')

    if not (algos := config.get_jwt_algorithm_by_tenant(tenant)):
        raise Exception(f'Cannot get JWT algorithms for tenant "{tenant}" from config.')

    try:
        # 10s leeway as clock skew margin
        payload = jwt.decode(
            jwt_token, cert,
            leeway=10,
            audience=aud,
            algorithms=algos,
            options={
                'require_exp': True,
                'verify_signature': True,
                'verify_exp': True
                }
            )
    except jwt.InvalidSignatureError as e:
        logger.error(
            f'Unauthorized login attempt using invalid public key: {e}')
        return '', ''
    except jwt.ExpiredSignatureError as e:
        logger.error(
            f'Cannot authorize request, because the JWT has expired: {e}')
        return '', ''

    logger.debug(f'Successfully decoded JWT payload: {payload}')

    return payload.get('sub', ''), payload.get('iss', '')


def _authenticate(tenant: str, header: EnvironHeaders) -> str:
    """
    Authentication requires a bearer token in JWT format.

    JWT signature verification might not be required at this point,
    because it is done by Vault as well.
    However, it might be useful to implement a vault access token<->jwt cache,
    which requires to authenticate here as well.
    """

    if not (token := _get_jwt_from_header(header)):
        logger.error('Cannot get JWT from request.')
        logger.debug(f'Request header: {header}')
        return ''

    if not (jwt_kid := _get_kid_from_jwt(token)):
        logger.error('Cannot get kid from JWT.')
        logger.debug(f'JWT: {token}')
        return ''

    logger.info(f'Attempting to authenticate JWT with kid "{jwt_kid}"...')

    if not (validation_cert := config.get_jwt_validation_cert_by_tenant_and_kid(tenant, jwt_kid)):
        raise Exception(
                f'No validation certificate exists in config.json to verify signature for JWTs with kid "{jwt_kid}".')

    logger.debug(f'Attempting to validate JWT signature using cert "{validation_cert}".')

    # pyjwt[crypto] requires cert to be in PEM format & only the public key.
    # TODO: Extract key from cert programmatically:
    #       https://pyjwt.readthedocs.io/en/latest/faq.html
    #           how-can-i-extract-a-public-private-key-from-a-x509-certificate
    cert = open(validation_cert).read()

    logger.debug(f'Received JWT: {token}')

    token_sub, token_iss = _decode_jwt(tenant, token, cert)

    if not (cfg_sub := config.get_jwt_subject_by_tenant(tenant)):
        raise Exception(f'Cannot get JWT subject for tenant "{tenant}" from config.')

    if not (cfg_iss := config.get_jwt_issuer_by_tenant(tenant)):
        raise Exception(f'Cannot get JWT issuer for tenant "{tenant}" from config.')

    if (token_sub == cfg_sub) and (token_iss == cfg_iss):
        logger.info(
            f'Successfully authenticated JWT (issuer: {token_iss}, subject: {token_sub}).')
        return token
    else:
        logger.error(
            f'Cannot authorize JWT. Wrong issuer "{token_iss}" or subject "{token_sub}".')
        return ''


@app.route(path_prefix + '<string:tenant>/<string:jwe_kid>', methods=['GET'])
def get_wrapped_key(tenant: str = '', jwe_kid: str = ''):
    """
    tenant: Tenant (key consumer) that makes a request. E.g. Salesforce. Mandatory.
    jwe_kid: kid provided by Salesforce. Mandatory.
    nonce: Nonce (?requestId=x) provided by Salesforce (to prevent replay attacks). Optional.
    """

    if not (token := _authenticate(tenant, request.headers)):
        if not (jwt_audience := config.get_jwt_audience_by_tenant(tenant)):
            jwt_audience = 'unknown'

        # WWW-Authenticate header according to: https://tools.ietf.org/html/rfc6750#section-3
        return Response(
            response=f'Unauthorized request from {request.headers["X-Real-Ip"]}, ({request.user_agent}).',
            status=401,
            content_type='text/html; charset=utf-8',
            headers={'WWW-Authenticate': f'Bearer scope="{jwt_audience}"'})

    logger.info(f'Processing request (path: "{request.path}", args: "{request.args.to_dict()}"...')

    json_jwe_token = jwe.get_wrapped_key_as_jwe(
        token,
        str(escape(tenant)),
        str(escape(jwe_kid)),
        str(escape(request.args.get('requestId', ''))))

    if not json_jwe_token:
        return 'Oops, internal error.', 500

    logger.info(
        f'JWE token with kid "{json.loads(json_jwe_token)["kid"]}" sent.',)
    logger.debug(
        f'JWE token: {json_jwe_token}',)

    resp = Response(
        response=json_jwe_token,
        status=200,
        content_type='application/json; charset=utf-8')

    return resp
