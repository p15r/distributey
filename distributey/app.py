from markupsafe import escape
from flask import Flask
from flask import Response
import json
import jwt
from os import getpid
from typing import Tuple, Dict
from webargs.flaskparser import use_args
from flask import abort

import jwe
import config
import vault_backend
import input_validation


app = Flask(__name__)

# Set up logging
app.logger.handlers.clear()
# Bcs of modules import such as jwe, vault_backend, etc.
# dy_logging.__streamHandler has already been added to root logger,
# thus this is not required and would add the handler twice:
# app.logger.addHandler(dy_logging.__stream_handler)

app.logger.info(f'🚀 distributey is starting (pid {getpid()})...')

# URL-based API versioning
base_path = '/'
api_versioning_path = 'v1/'
path_prefix = base_path + api_versioning_path


def __http_error(status_code: int, msg: str) -> None:
    resp = Response(
        response=msg,
        status=status_code,
        content_type='application/json; charset=utf-8')

    abort(resp)


def _get_kid_from_jwt(token: str) -> str:
    try:
        protected_header_unverified = jwt.get_unverified_header(token)
    except jwt.DecodeError as e:
        app.logger.error(f'Cannot decode JWT in order to get kid: {e}')
        app.logger.debug(f'JWT: {token}')
        return ''

    return protected_header_unverified.get('kid', '')


def _get_jwt_from_header(token: str) -> str:
    if not token.startswith('Bearer'):
        app.logger.error('Cannot fetch Bearer token from Authorization header.')
        app.logger.debug(f'Malformed token w/o Bearer: {token}')
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
        app.logger.error(f'Cannot get JWT audience for tenant "{tenant}" from config.')
        __http_error(500, '{"error": "internal error"}')

    if not (algos := config.get_jwt_algorithm_by_tenant(tenant)):
        app.logger.error(f'Cannot get JWT algorithms for tenant "{tenant}" from config.')
        __http_error(500, '{"error": "internal error"}')

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
        app.logger.error(
            f'Unauthorized login attempt using invalid public key: {e}')
        return '', ''
    except jwt.ExpiredSignatureError as e:
        app.logger.error(
            f'Cannot authorize request, because the JWT has expired: {e}')
        return '', ''

    app.logger.debug(f'Successfully decoded JWT payload: {payload}')

    return payload.get('sub', ''), payload.get('iss', '')


def _authenticate(tenant: str, auth_header: str) -> str:
    """
    Authentication requires a bearer token in JWT format.

    JWT signature verification might not be required at this point,
    because it is done by Vault as well.
    However, it might be useful to implement a vault access token<->jwt cache,
    which requires to authenticate here as well.
    """

    if not (token := _get_jwt_from_header(auth_header)):
        app.logger.error('Cannot get JWT from request.')
        app.logger.debug(f'Request header: {auth_header}')
        return ''

    if not (jwt_kid := _get_kid_from_jwt(token)):
        app.logger.error('Cannot get kid from JWT.')
        app.logger.debug(f'JWT: {token}')
        return ''

    app.logger.info(f'Attempting to authenticate JWT with kid "{jwt_kid}"...')

    if not (validation_cert := config.get_jwt_validation_cert_by_tenant_and_kid(tenant, jwt_kid)):
        app.logger.error(
                f'No validation certificate exists in config.json to verify signature for JWTs with kid "{jwt_kid}".')

        __http_error(500, '{"error": "internal error"}')

    app.logger.debug(f'Attempting to validate JWT signature using cert "{validation_cert}".')

    # pyjwt[crypto] requires cert to be in PEM format & only the public key.
    # TODO: Extract key from cert programmatically:
    #       https://pyjwt.readthedocs.io/en/latest/faq.html
    #           how-can-i-extract-a-public-private-key-from-a-x509-certificate
    cert = open(validation_cert).read()

    app.logger.debug(f'Received JWT: {token}')

    token_sub, token_iss = _decode_jwt(tenant, token, cert)

    if not (cfg_sub := config.get_jwt_subject_by_tenant(tenant)):
        app.logger.error(f'Cannot get JWT subject for tenant "{tenant}" from config.')
        __http_error(500, '{"error": "internal error"}')

    if not (cfg_iss := config.get_jwt_issuer_by_tenant(tenant)):
        app.logger.error(f'Cannot get JWT issuer for tenant "{tenant}" from config.')
        __http_error(500, '{"error": "internal error"}')

    if (token_sub == cfg_sub) and (token_iss == cfg_iss):
        app.logger.info(
            f'Successfully authenticated JWT (issuer: {token_iss}, subject: {token_sub}).')
        return token
    else:
        app.logger.error(
            f'Cannot authorize JWT. Wrong issuer "{token_iss}" or subject "{token_sub}".')
        return ''


def _get_dek_from_vault(jwt_token: str, tenant: str, jwe_kid: str) -> bytes:
    if not (vault_path := config.get_vault_path_by_tenant_and_kid(tenant, jwe_kid)):
        # kid not found in config,
        # assume kid and vault path are the same
        # and fetch latest version of secret
        vault_path = jwe_kid + ':latest'

    app.logger.debug(f'Fetching AES key for: {vault_path}')

    vault_key, key_version = vault_path.split(':')

    if not (dek := vault_backend.get_dynamic_secret(tenant, vault_key, key_version, jwt_token)):
        app.logger.error(f'Cannot retrieve key "{vault_path}".')
        return b''

    if config.get_config_by_key('DEV_MODE'):
        app.logger.debug(f'Retrieved key from Vault: {dek.hex()} (hex)')

    return dek


# TODO: write tests for check input validation


@app.route(path_prefix + '<string:tenant>/<string:jwe_kid>', methods=['GET'])
@use_args(input_validation.view_args, location='view_args')  # view_args: part of request.path
@use_args(input_validation.query_args, location='query')
@use_args(input_validation.header_args, location='headers')
def get_wrapped_key(
        view_args: Dict, query_args: Dict, header_args: Dict, *args, **kwargs):
    """
    tenant: Tenant (key consumer) that makes a request. E.g. Salesforce. Mandatory.
    jwe_kid: kid provided by Salesforce. Mandatory.
    nonce: Nonce (?requestId=x) provided by Salesforce (to prevent replay attacks). Optional.
    """

    if not (token := _authenticate(view_args['tenant'], header_args['jwt'])):
        if not (jwt_audience := config.get_jwt_audience_by_tenant(view_args['tenant'])):
            jwt_audience = 'unknown'

        error_msg = (f'Unauthorized request fem {header_args["x-real-ip"]} '
                     f'({header_args["user-agent"]}).')

        # WWW-Authenticate header according to: https://tools.ietf.org/html/rfc6750#section-3
        return Response(
            response=json.dumps({
                'error': 401,
                'error_message': error_msg}),
            status=401,
            content_type='application/json; charset=utf-8',
            headers={'WWW-Authenticate': f'Bearer scope="{jwt_audience}"'})

    # TODO: should I do that on webargs instead?
    tenant = str(escape(view_args['tenant']))
    jwe_kid = str(escape(view_args['jwe_kid']))
    nonce = str(escape(query_args['requestId']))

    dek = _get_dek_from_vault(token, tenant, jwe_kid)

    json_jwe_token = jwe.get_wrapped_key_as_jwe(dek, tenant, jwe_kid, nonce)

    del dek

    if not json_jwe_token:
        return 'Oops, internal error.', 500

    app.logger.info(
        f'JWE token with kid "{json.loads(json_jwe_token)["kid"]}" sent.',)
    app.logger.debug(
        f'JWE token: {json_jwe_token}',)

    resp = Response(
        response=json_jwe_token,
        status=200,
        content_type='application/json; charset=utf-8')

    return resp


@app.route(path_prefix + '/healthz', methods=['GET'])
def get_healthz():
    """
    This healthz implementation adheres to:
        https://tools.ietf.org/html/draft-inadarei-api-health-check-04
    """

    if not config.get_config_by_key('LOG_LEVEL'):
        response = '{"status": "fail", "output": "Config not loaded"}'
        status = 500
    else:
        response = '{"status": "pass"}'
        status = 200

    return Response(response=response, status=status, content_type='application/health+json; charset=utf-8')
