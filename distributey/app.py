"""Contains the Flask app that serves distributey's API."""

from pathlib import Path
import json
import os
from os import getpid
from typing import Tuple, Dict
import inspect
from webargs.flaskparser import use_args
from markupsafe import escape
from flask import Flask, Response, abort, session
from dy_trace import trace_enter, trace_exit, CAMOUFLAGE_SIGN
import jwt
import jwe
import vault_backend
import input_validation
import config
import utils


app = Flask(__name__)
app.secret_key = os.urandom(32)

app.logger.info('🚀 distributey is starting (pid %d)...', getpid())

# URL-based API versioning
__BASE_PATH = '/'
__API_VERSIONING_PATH = 'v1/'
__PATH_PREFIX = __BASE_PATH + __API_VERSIONING_PATH

# DB to temporarily store nonces
__CACHE_DB = '/tmp/cache.db'    # NOSONAR
__CACHE_DB_NR_ENTRIES = 10000


def _dev_mode_warning_banner() -> None:
    trace_enter(inspect.currentframe())

    dev_mode = config.get_config_by_keypath('DEV_MODE')
    log_level = config.get_config_by_keypath('LOG_LEVEL')

    banner = r"""

      _____  ________      __  __  __  ____  _____  ______
     |  __ \|  ____\ \    / / |  \/  |/ __ \|  __ \|  ____|
     | |  | | |__   \ \  / /  | \  / | |  | | |  | | |__
     | |  | |  __|   \ \/ /   | |\/| | |  | | |  | |  __|
     | |__| | |____   \  /    | |  | | |__| | |__| | |____
     |_____/|______|   \/     |_|  |_|\____/|_____/|______|

     Sensitive data, such as data encryption keys are logged in plain-text.

     """

    if dev_mode and log_level == 'debug':
        app.logger.info(banner)

    trace_exit(inspect.currentframe(), None)


_dev_mode_warning_banner()


def _initialize_cache_db() -> bool:
    """Init temporary database to store nonces to prevent replay attacks."""
    trace_enter(inspect.currentframe())

    cache_db = Path(__CACHE_DB)

    if cache_db.is_file():
        ret = True
        trace_exit(inspect.currentframe(), ret)
        return ret

    try:
        # create empty file
        with open(__CACHE_DB, 'a') as file:
            file.write('')
    except Exception as exc:
        ret = False
        app.logger.error('Failed to create cache db: %s', exc)
        trace_exit(inspect.currentframe(), ret)
        return ret

    ret = True
    trace_exit(inspect.currentframe(), ret)
    return ret


if not _initialize_cache_db():
    trace_enter(inspect.currentframe())

    app.logger.error('Failed to initialize cache db. Aborting...')

    trace_exit(inspect.currentframe(), None)
    # sys.exit(1)
    raise SystemExit(1)


def _http_error(status_code: int, msg: str, headers: dict = None) -> None:
    trace_enter(inspect.currentframe())

    ret = Response(
        response=msg,
        status=status_code,
        content_type='application/json; charset=utf-8',
        headers=headers)

    trace_exit(inspect.currentframe(), ret)
    abort(ret)


def _http_20x(status_code: int, msg: str, headers: dict = None) -> Response:
    trace_enter(inspect.currentframe())

    ret = Response(
        response=msg,
        status=status_code,
        content_type='application/json; charset=utf-8',
        headers=headers)

    trace_exit(inspect.currentframe(), ret)
    return ret


def _get_jwt_from_header(priv_token: str) -> str:
    trace_enter(inspect.currentframe())

    if not priv_token.startswith('Bearer'):
        ret = ''
        app.logger.error('Cannot fetch Bearer token from Authorization '
                         'header.')
        app.logger.debug('Malformed token w/o Bearer: %s', priv_token)
        trace_exit(inspect.currentframe(), ret)
        return ret

    parts = priv_token.split('Bearer')

    if len(parts) != 2:
        ret = ''
        app.logger.error('Token format does not match "Bearer Token".')
        trace_exit(inspect.currentframe(), ret)
        return ret

    if len(parts[1].strip()) == 0:
        ret = ''
        app.logger.error('Found "Bearer" string in auth header, but no JWT.')
        trace_exit(inspect.currentframe(), ret)
        return ret

    ret = parts[1].strip()

    trace_exit(inspect.currentframe(), CAMOUFLAGE_SIGN)
    return ret


def _decode_jwt(tenant: str, priv_jwt_token: str, cert: str) \
        -> Tuple[str, str]:
    """
    The jwt_token must...
    - have a valid signature,
    - contain 'iss' & 'sub' claims
    - not have expired (leeway of 10s for clock skew is tolerated)
    """
    trace_enter(inspect.currentframe())

    if not (aud := config.get_jwt_audience_by_tenant(tenant)):
        app.logger.error('Cannot get JWT audience for tenant "%s" from '
                         'config.', tenant)
        trace_exit(inspect.currentframe(), ('', ''))
        _http_error(500, '{"error": "internal error"}')

    if not (algos := config.get_jwt_algorithm_by_tenant(tenant)):
        app.logger.error('Cannot get JWT algorithms for tenant "%s" from '
                         'config.', tenant)
        trace_exit(inspect.currentframe(), ('', ''))
        _http_error(500, '{"error": "internal error"}')

    try:
        # 10s leeway as clock skew margin
        payload = jwt.decode(
            priv_jwt_token,
            cert,
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
        ret = ('', '')
        app.logger.error('Unauthorized login attempt using invalid public key:'
                         '%s', exc)
        trace_exit(inspect.currentframe(), ret)
        return ret
    except jwt.ExpiredSignatureError as exc:
        ret = ('', '')
        app.logger.error('Unauthorized login attempt using an expired JWT: '
                         '%s', exc)
        trace_exit(inspect.currentframe(), ret)
        return ret
    except jwt.InvalidAudienceError as exc:
        ret = ('', '')
        app.logger.error('Unauthorized login attempt using invalid audience '
                         'claim: %s', exc)
        trace_exit(inspect.currentframe(), ret)
        return ret

    app.logger.debug('Successfully decoded JWT payload: %s', payload)

    ret = payload.get('sub', ''), payload.get('iss', '')
    trace_exit(inspect.currentframe(), ret)
    return ret


def _is_replay_attack(nonce: str) -> bool:
    # TODO: Protect against: https://rules.sonarsource.com/python/RSPEC-5445
    #       However, keep in mind that tempfile.NamedTemporaryFile() would
    #       create a cache db per thread, instead of one global db.
    #       Risk is acceptable since application runs in dedicated container.

    try:
        with open(__CACHE_DB, 'r') as file:
            used_nonces = file.read()
    except Exception as exc:
        ret = True
        app.logger.error('Failed to read from replay attack cache db: %s', exc)
        trace_exit(inspect.currentframe(), ret)
        return ret

    deny_list = used_nonces.split('\n')

    if nonce in deny_list:
        ret = True
        app.logger.error('Replay attack detected using nonce: %s', nonce)
        trace_exit(inspect.currentframe(), ret)
        return ret

    if len(deny_list) >= __CACHE_DB_NR_ENTRIES+1:
        # remove first cache entry
        deny_list.pop(0)

    deny_list.append(nonce)
    denied_nonces = '\n'.join(deny_list)

    try:
        with open(__CACHE_DB, 'w') as file:
            file.write(denied_nonces)
    except Exception as exc:
        ret = True
        app.logger.error('Failed to write replay attack cache db: %s', exc)
        trace_exit(inspect.currentframe(), ret)
        return ret

    trace_exit(inspect.currentframe(), False)
    return False


def _authenticate(tenant: str, priv_auth_header: str) -> str:
    """
    Authentication requires a bearer token in JWT format.
    """
    trace_enter(inspect.currentframe())

    if not (token := _get_jwt_from_header(priv_auth_header)):
        ret = ''
        app.logger.error('Cannot get JWT from request.')
        app.logger.debug('Request header: %s', priv_auth_header)
        trace_exit(inspect.currentframe(), ret)
        return ret

    if not (jwt_kid := utils.get_kid_from_jwt(token)):
        ret = ''
        app.logger.error('Cannot get kid from JWT.')
        app.logger.debug('JWT: %s', token)
        trace_exit(inspect.currentframe(), ret)
        return ret

    app.logger.info('Attempting to authenticate JWT with kid "%s"...', jwt_kid)

    if not (validation_cert :=
            config.get_jwt_validation_cert_by_tenant_and_kid(tenant, jwt_kid)):
        ret = ''
        app.logger.error('No validation certificate exists in config.json to '
                         'verify signature for JWTs with kid "%s".', jwt_kid)
        trace_exit(inspect.currentframe(), ret)
        _http_error(500, '{"error": "internal error"}')

    app.logger.debug('Attempting to validate JWT signature using cert "%s".',
                     validation_cert)

    # pyjwt[crypto] requires PEM format & only the public key.
    # TODO: Extract key from cert programmatically:
    #       https://pyjwt.readthedocs.io/en/latest/faq.html
    #           how-can-i-extract-a-public-private-key-from-a-x509-certificate
    try:
        with open(validation_cert) as file:
            cert = file.read()
    except Exception as exc:
        ret = ''
        app.logger.error('Failed to read validation cert: %s', exc)
        trace_exit(inspect.currentframe(), ret)
        _http_error(500, '{"error": "internal error"}')

    app.logger.debug('Received JWT: %s', token)

    token_sub, token_iss = _decode_jwt(tenant, token, cert)

    if not (cfg_sub := config.get_jwt_subject_by_tenant(tenant)):
        ret = ''
        app.logger.error('Cannot get JWT subject for tenant "%s" from config.',
                         tenant)
        trace_exit(inspect.currentframe(), ret)
        _http_error(500, '{"error": "internal error"}')

    if not (cfg_iss := config.get_jwt_issuer_by_tenant(tenant)):
        ret = ''
        app.logger.error('Cannot get JWT issuer for tenant "%s" from config.',
                         tenant)
        trace_exit(inspect.currentframe(), ret)
        _http_error(500, '{"error": "internal error"}')

    if (token_sub == cfg_sub) and (token_iss == cfg_iss):
        app.logger.info('Successfully authenticated JWT issuer: %s, '
                        'subject: %s).', token_iss, token_sub)
        trace_exit(inspect.currentframe(), CAMOUFLAGE_SIGN)
        return token

    app.logger.error('Cannot authorize JWT. Wrong issuer "%s" or '
                     'subject "%s".', token_iss, token_sub)

    ret = ''
    trace_exit(inspect.currentframe(), ret)
    return ret


def _get_dek_from_vault(priv_jwt_token: str, tenant: str,
                        jwe_kid: str) -> bytearray:
    trace_enter(inspect.currentframe())

    if not (vault_path := config.get_vault_path_by_tenant_and_kid(
            tenant, jwe_kid)):
        # kid not found in config,
        # assume kid and vault path are the same
        # and fetch latest version of secret
        vault_path = jwe_kid + ':latest'

    app.logger.debug('Fetching AES key for: %s', vault_path)

    vault_key, key_version = vault_path.split(':')

    if not (dek := vault_backend.get_dynamic_secret(
            tenant, vault_key, key_version, priv_jwt_token)):
        ret = bytearray()
        app.logger.error('Cannot retrieve key "%s".', vault_path)
        trace_exit(inspect.currentframe(), ret)
        return ret

    if config.get_config_by_keypath('DEV_MODE'):
        app.logger.debug('Retrieved key from Vault: %s (hex)', dek.hex())

    trace_exit(inspect.currentframe(), CAMOUFLAGE_SIGN)
    return dek


# view_args: part of HTTP request.path
# **kwargs catches "tenant" & jwe_kid; disregard because not filtered
@app.route(__PATH_PREFIX + '<string:tenant>/<string:jwe_kid>', methods=['GET'])
@use_args(input_validation.VIEW_ARGS, location='view_args')
@use_args(input_validation.QUERY_ARGS, location='query')
@use_args(input_validation.HEADER_ARGS, location='headers')
def get_wrapped_key(view_args: Dict, query_args: Dict, header_args: Dict,
                    **kwargs):
    """
    tenant:     Tenant (key consumer) that makes a request. E.g. Salesforce.
                Mandatory.
    jwe_kid:    kid provided by key consumer. Mandatory.
    nonce:      Nonce (?requestId=x) provided by key consumer
                (to prevent replay attacks). Mandatory.
    """
    trace_enter(inspect.currentframe())

    session['view_args'] = view_args
    session['query_args'] = query_args
    session['header_args'] = header_args

    if _is_replay_attack(query_args['requestId']):
        ret = ''
        err_msg = 'Replay attack detected for nonce: %s' % \
            query_args['requestId']

        app.logger.error(err_msg)

        ret = '{"status": "fail", "output": "%s"}' % err_msg
        trace_exit(inspect.currentframe(), ret)
        _http_error(500, ret)

    if not (token := _authenticate(view_args['tenant'],
                                   header_args['priv_jwt'])):
        if not (jwt_audience := config.get_jwt_audience_by_tenant(
                view_args['tenant'])):
            jwt_audience = 'unknown'

        err_msg = ('Unauthorized request from %s (%s).' %
                   (header_args['x-real-ip'], header_args['user-agent']))

        http_err_msg = '{ "status": "fail", "output": "%s"}' % err_msg

        # WWW-Authenticate header according to:
        #   https://tools.ietf.org/html/rfc6750#section-3
        header = {'WWW-Authenticate': f'Bearer scope="{jwt_audience}"'}

        trace_exit(inspect.currentframe(), http_err_msg)
        _http_error(401, http_err_msg, header)

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
        err_msg = 'Failed to retrieve key material from key service.'
        app.logger.error(err_msg)
        ret = '{"status": "fail", "output": "%s"}' % err_msg

        trace_exit(inspect.currentframe(), ret)
        _http_error(500, ret)

    try:
        json_jwe_token = jwe.get_wrapped_key_as_jwe(dek, tenant, jwe_kid,
                                                    nonce)
    except Exception as exc:
        ret = '{"status": "fail", "output": "Oops, internal error."}'
        app.logger.error('Failed to create JWE: %s', exc)
        trace_exit(inspect.currentframe(), ret)
        _http_error(500, ret)

    if not json_jwe_token:
        ret = '{"status": "fail", "output": "Oops, internal error."}'
        app.logger.error('Failed to create JWE for unknown reason.')
        trace_exit(inspect.currentframe(), ret)
        _http_error(500, ret)

    app.logger.info('JWE token with kid "%s" sent.',
                    json.loads(json_jwe_token)['kid'])
    app.logger.debug('JWE token: %s', json_jwe_token)

    ret_resp = _http_20x(200, json_jwe_token)

    trace_exit(inspect.currentframe(), ret_resp)
    return ret_resp


@app.route(__PATH_PREFIX + '/healthz', methods=['GET'])
def get_healthz():
    """
    This healthz implementation adheres to:
        https://tools.ietf.org/html/draft-inadarei-api-health-check-04

    TODO: add user-agent & x-real-ip to input validation &
          flask.session in order to log request properly.
    """
    trace_enter(inspect.currentframe())

    if not config.get_config_by_keypath('LOG_LEVEL'):
        ret = '{"status": "fail", "output": "Config not loaded"}'
        trace_exit(inspect.currentframe(), ret)
        _http_error(500, ret)

    ret = _http_20x(200, '{"status": "pass"}')

    trace_exit(inspect.currentframe(), ret)
    return ret
