"""Contains the Flask app that serves distributey's API."""

import json
import os
from os import getpid
from typing import Tuple, Dict
import inspect
from webargs.flaskparser import use_args
from markupsafe import escape
from flask import Flask
from flask import Response
from flask import abort
from flask import session
from dy_trace import trace_enter, trace_exit, CAMOUFLAGE_SIGN
import jwt
import jwe
import vault_backend
import input_validation
import config


app = Flask(__name__)
app.secret_key = os.urandom(16)

# Set up logging
app.logger.handlers.clear()
# Bcs of modules import such as jwe, vault_backend, etc.
# dy_logging.__streamHandler has already been added to root logger,
# thus this is not required and would add the handler twice:
# app.logger.addHandler(dy_logging.__stream_handler)

app.logger.info('🚀 distributey is starting (pid %d)...', getpid())

# URL-based API versioning
BASE_PATH = '/'
API_VERSIONING_PATH = 'v1/'
PATH_PREFIX = BASE_PATH + API_VERSIONING_PATH


def __http_error(status_code: int, msg: str) -> None:
    trace_enter(inspect.currentframe())

    resp = Response(
        response=msg,
        status=status_code,
        content_type='application/json; charset=utf-8')

    trace_exit(inspect.currentframe(), resp)
    abort(resp)


def _get_kid_from_jwt(priv_token: str) -> str:
    trace_enter(inspect.currentframe())

    try:
        protected_header_unverified = jwt.get_unverified_header(priv_token)
    except jwt.DecodeError as exc:
        app.logger.error('Cannot decode JWT in order to get kid: %s', exc)
        app.logger.debug('JWT: %s', priv_token)
        return ''

    ret = protected_header_unverified.get('kid', '')
    trace_exit(inspect.currentframe(), ret)
    return ret


def _get_jwt_from_header(priv_token: str) -> str:
    trace_enter(inspect.currentframe())

    if not priv_token.startswith('Bearer'):
        app.logger.error('Cannot fetch Bearer token from Authorization '
                         'header.')
        app.logger.debug('Malformed token w/o Bearer: %s', priv_token)
        return ''

    parts = priv_token.split('Bearer')

    if len(parts) != 2:
        app.logger.error('Token format does not match "Bearer Token".')
        ret = ''
        trace_exit(inspect.currentframe(), ret)
        return ret

    ret = parts[1].strip()

    trace_exit(inspect.currentframe(), CAMOUFLAGE_SIGN)
    return ret


def _decode_jwt(tenant: str, priv_jwt_token: str, cert: str) -> Tuple[str, str]:
    """
    The jwt_token must..
    - have a valid signature,
    - contain 'iss' & 'sub' claims
    - not have expired (leeway of 10s for clock skew is tolerated)
    """
    trace_enter(inspect.currentframe())

    if not (aud := config.get_jwt_audience_by_tenant(tenant)):
        app.logger.error('Cannot get JWT audience for tenant "%s" from '
                         'config.', tenant)
        __http_error(500, '{"error": "internal error"}')

    if not (algos := config.get_jwt_algorithm_by_tenant(tenant)):
        app.logger.error('Cannot get JWT algorithms for tenant "%s" from '
                         'config.', tenant)
        __http_error(500, '{"error": "internal error"}')

    try:
        # 10s leeway as clock skew margin
        payload = jwt.decode(
            priv_jwt_token, cert,
            leeway=10,
            audience=aud,
            algorithms=algos,
            options={
                'require_exp': True,
                'verify_signature': True,
                'verify_exp': True
                }
            )
    except jwt.InvalidSignatureError as exc:
        app.logger.error('Unauthorized login attempt using invalid public key:'
                         '%s', exc)
        trace_exit(inspect.currentframe(), ('', ''))
        return '', ''
    except jwt.ExpiredSignatureError as exc:
        app.logger.error('Cannot authorize request, because the JWT has '
                         'expired: %s', exc)
        trace_exit(inspect.currentframe(), ('', ''))
        return '', ''

    app.logger.debug('Successfully decoded JWT payload: %s', payload)

    ret = payload.get('sub', ''), payload.get('iss', '')
    trace_exit(inspect.currentframe(), ret)
    return ret


def _authenticate(tenant: str, priv_auth_header: str) -> str:
    """
    Authentication requires a bearer token in JWT format.

    JWT signature verification might not be required at this point,
    because it is done by Vault as well.
    However, it might be useful to implement a vault access token<->jwt cache,
    which requires to authenticate here as well.
    """
    trace_enter(inspect.currentframe())

    if not (token := _get_jwt_from_header(priv_auth_header)):
        app.logger.error('Cannot get JWT from request.')
        app.logger.debug('Request header: %s', priv_auth_header)
        trace_exit(inspect.currentframe(), '')
        return ''

    if not (jwt_kid := _get_kid_from_jwt(token)):
        app.logger.error('Cannot get kid from JWT.')
        app.logger.debug('JWT: %s', token)
        trace_exit(inspect.currentframe(), '')
        return ''

    app.logger.info('Attempting to authenticate JWT with kid "%s"...', jwt_kid)

    if not (validation_cert :=
            config.get_jwt_validation_cert_by_tenant_and_kid(tenant, jwt_kid)):
        app.logger.error('No validation certificate exists in config.json to '
                         'verify signature for JWTs with kid "%s".', jwt_kid)

        __http_error(500, '{"error": "internal error"}')

    app.logger.debug('Attempting to validate JWT signature using cert "%s".',
                     validation_cert)

    # pyjwt[crypto] requires cert to be in PEM format & only the public key.
    # TODO: Extract key from cert programmatically:
    #       https://pyjwt.readthedocs.io/en/latest/faq.html
    #           how-can-i-extract-a-public-private-key-from-a-x509-certificate
    cert = open(validation_cert).read()

    app.logger.debug('Received JWT: %s', token)

    token_sub, token_iss = _decode_jwt(tenant, token, cert)

    if not (cfg_sub := config.get_jwt_subject_by_tenant(tenant)):
        app.logger.error('Cannot get JWT subject for tenant "%s" from config.',
                         tenant)
        __http_error(500, '{"error": "internal error"}')

    if not (cfg_iss := config.get_jwt_issuer_by_tenant(tenant)):
        app.logger.error('Cannot get JWT issuer for tenant "%s" from config.',
                         tenant)
        __http_error(500, '{"error": "internal error"}')

    if (token_sub == cfg_sub) and (token_iss == cfg_iss):
        app.logger.info('Successfully authenticated JWT issuer: %s, '
                        'subject: %s).', token_iss, token_sub)
        trace_exit(inspect.currentframe(), CAMOUFLAGE_SIGN)
        return token

    app.logger.error('Cannot authorize JWT. Wrong issuer "%s" or '
                     'subject "%s".', token_iss, token_sub)
    trace_exit(inspect.currentframe(), '')
    return ''


def _get_dek_from_vault(priv_jwt_token: str, tenant: str,
                        jwe_kid: str) -> bytes:
    trace_enter(inspect.currentframe())

    if not (vault_path := config.get_vault_path_by_tenant_and_kid(tenant, jwe_kid)):
        # kid not found in config,
        # assume kid and vault path are the same
        # and fetch latest version of secret
        vault_path = jwe_kid + ':latest'

    app.logger.debug('Fetching AES key for: %s', vault_path)

    vault_key, key_version = vault_path.split(':')

    if not (dek := vault_backend.get_dynamic_secret(
            tenant, vault_key, key_version, priv_jwt_token)):
        app.logger.error('Cannot retrieve key "%s".', vault_path)
        trace_exit(inspect.currentframe(), b'')
        return b''

    if config.get_config_by_keypath('DEV_MODE'):
        app.logger.debug('Retrieved key from Vault: %s (hex)', dek.hex())

    trace_exit(inspect.currentframe(), CAMOUFLAGE_SIGN)
    return dek


# view_args: part of request.path
# **kwargs catches "tenant" & jwe_kid; disregard because not filtered
@app.route(PATH_PREFIX + '<string:tenant>/<string:jwe_kid>', methods=['GET'])
@use_args(input_validation._VIEW_ARGS, location='view_args')
@use_args(input_validation._QUERY_ARGS, location='query')
@use_args(input_validation._HEADER_ARGS, location='headers')
def get_wrapped_key(view_args: Dict, query_args: Dict, header_args: Dict,
                    **kwargs):
    """
    tenant:     Tenant (key consumer) that makes a request. E.g. Salesforce.
                Mandatory.
    jwe_kid:    kid provided by Salesforce. Mandatory.
    nonce:      Nonce (?requestId=x) provided by Salesforce
                (to prevent replay attacks). Optional.
    """
    trace_enter(inspect.currentframe())
    session['view_args'] = view_args
    session['query_args'] = query_args
    session['header_args'] = header_args

    if not (token := _authenticate(view_args['tenant'], header_args['priv_jwt'])):
        if not (jwt_audience := config.get_jwt_audience_by_tenant(
                view_args['tenant'])):
            jwt_audience = 'unknown'

        error_msg = (f'Unauthorized request from {header_args["x-real-ip"]} '
                     f'({header_args["user-agent"]}).')

        ret = Response(
            response=json.dumps({
                'error': 401,
                'error_message': error_msg}),
            status=401,
            content_type='application/json; charset=utf-8',
            headers={'WWW-Authenticate': f'Bearer scope="{jwt_audience}"'})

        trace_exit(inspect.currentframe(), ret)

        # WWW-Authenticate header according to:
        #   https://tools.ietf.org/html/rfc6750#section-3
        return ret

    if app.config.get('TESTING', ''):
        # FIXME: For some reason, query_args is empty if Flask is executed
        #        as unittest client
        #        (strangely, view_args & header_args have proper values).
        #        query_args must have proper values for unittest
        #        "test___jwt_validator()".
        query_args = {'requestId': 'randomstring'}

    tenant = str(escape(view_args['tenant']))
    jwe_kid = str(escape(view_args['jwe_kid']))
    nonce = str(escape(query_args['requestId']))

    dek = _get_dek_from_vault(token, tenant, jwe_kid)

    if not dek:
        err_msg = 'Failed to retrieve key material from Vault.'
        app.logger.error(err_msg)
        ret = Response(
            response=json.dumps({'status': 'fail', 'output': err_msg}),
            status=500,
            content_type='application/json; charset=utf-8')

        trace_exit(inspect.currentframe(), ret)
        return ret

    try:
        json_jwe_token = jwe.get_wrapped_key_as_jwe(dek, tenant, jwe_kid, nonce)
    except Exception as exc:
        app.logger.error('Failed to create JWE: %s', exc)
        ret = Response(
            response='Oops, internal error.',
            status=500,
            content_type='application/json; charset=utf-8')
        trace_exit(inspect.currentframe(), ret)
        return ret

    del dek

    if not json_jwe_token:
        ret = Response(
            response='Oops, internal error.',
            status=500,
            content_type='application/json; charset=utf-8')
        trace_exit(inspect.currentframe(), ret)
        return ret

    app.logger.info('JWE token with kid "%s" sent.',
                    json.loads(json_jwe_token)['kid'])
    app.logger.debug('JWE token: %s', json_jwe_token)

    ret = Response(
        response=json_jwe_token,
        status=200,
        content_type='application/json; charset=utf-8')

    trace_exit(inspect.currentframe(), ret)
    return ret


@app.route(PATH_PREFIX + '/healthz', methods=['GET'])
def get_healthz():
    """
    This healthz implementation adheres to:
        https://tools.ietf.org/html/draft-inadarei-api-health-check-04

    TODO: add user-agent & x-real-ip to input validation &
          flask.session in order to log request properly.
    """
    trace_enter(inspect.currentframe())

    if not config.get_config_by_keypath('LOG_LEVEL'):
        response = '{"status": "fail", "output": "Config not loaded"}'
        status = 500
    else:
        response = '{"status": "pass"}'
        status = 200

    ret = Response(
        response=response, status=status,
        content_type='application/health+json; charset=utf-8')

    trace_exit(inspect.currentframe(), ret)
    return ret
