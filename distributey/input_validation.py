"""Input validation for distributey API."""

import base64
import json
from typing import Mapping
import inspect
import re
from flask import abort, Response
from webargs import ValidationError
from webargs.flaskparser import parser
from webargs import fields, validate
from marshmallow.exceptions import ValidationError as typeValidationError
from marshmallow.base import SchemaABC
import werkzeug
from dy_logging import logger
from dy_trace import trace_enter, trace_exit


# webargs error handler
@parser.error_handler
def __handle_request_parsing_error(
        validation_error: typeValidationError,
        request: werkzeug.local.LocalProxy,
        schema: SchemaABC,
        error_status_code: int = None,
        error_headers: Mapping[str, str] = None) -> None:
    """Handles errors, or raised exceptions respectively."""
    trace_enter(inspect.currentframe())

    input_data = validation_error.__dict__['data']

    logger.error(
        'Input validation failed with error "%s". '
        'Input: "%s".', validation_error, input_data)

    resp = Response(
        response=json.dumps(validation_error.__dict__['messages']),
        status=422,
        content_type='application/json; charset=utf-8')

    trace_exit(inspect.currentframe(), resp)
    abort(resp)


# various webargs validators
def __request_id_validator(request_id: str) -> None:
    # Replay attack detection specs of Salesforce's cache-only service:
    # https://developer.salesforce.com/docs/atlas.en-us.securityImplGuide.meta/
    #   securityImplGuide/security_pe_byok_cache_replay.htm
    trace_enter(inspect.currentframe())

    request_id_length = 32

    if len(request_id) != request_id_length:
        err_msg = ('requestId/nonce length must be %s alphanummeric '
                   'chars.' % request_id_length)
        logger.error(err_msg)
        trace_exit(inspect.currentframe(), err_msg)
        raise ValidationError(err_msg, status_code=422)

    result = re.match('^[a-zA-Z0-9]+$', request_id)

    if not result:
        err_msg = ('requestId/nonce must consist of alphanummeric chars only.')
        logger.error(err_msg)
        trace_exit(inspect.currentframe(), err_msg)
        raise ValidationError(err_msg, status_code=422)


def __user_agent_validator(user_agent: str) -> None:
    """
    Validates the user agent header.

    User agent specs: https://developer.mozilla.org/en-US/docs/Web/
        HTTP/Headers/User-Agent

    Enforce a minimum pattern of "uname/version".
    """
    trace_enter(inspect.currentframe())

    if len(user_agent) > 150:
        err_msg = 'User agent contains more than 150 characters.'
        logger.error(err_msg)
        trace_exit(inspect.currentframe(), err_msg)
        raise ValidationError(err_msg, status_code=422)

    parts = user_agent.split('/')

    err_msg = 'User agent pattern does not match "name/version"'
    if len(parts) < 2:
        logger.error(err_msg)
        trace_exit(inspect.currentframe(), err_msg)
        raise ValidationError(err_msg, status_code=422)

    if (len(parts[0]) < 1) or (len(parts[1]) < 1):
        logger.error(err_msg)
        trace_exit(inspect.currentframe(), err_msg)
        raise ValidationError(err_msg, status_code=422)


def __x_real_ip_validator(x_real_ip: str) -> None:
    """Validates the X-Real-IP header."""
    trace_enter(inspect.currentframe())

    if not 6 < len(x_real_ip) < 16:
        err_msg = 'X-Real-Ip must be between 7 and 15 characters long.'
        logger.error(err_msg)
        trace_exit(inspect.currentframe(), err_msg)
        raise ValidationError(err_msg, status_code=422)

    parts = x_real_ip.split('.')

    if len(parts) != 4:
        err_msg = ('X-Real-Ip format does not match: '
                   'digits.digits.digits.digits.')
        logger.error(err_msg)
        trace_exit(inspect.currentframe(), err_msg)
        raise ValidationError(err_msg, status_code=422)

    for part in parts:
        if not 0 < len(part) < 4:
            err_msg = ('X-Real-Ip format does not match: '
                       'x.x.x.x-xxx.xxx.xxx.xxx')
            logger.error(err_msg)
            trace_exit(inspect.currentframe(), err_msg)
            raise ValidationError(err_msg, status_code=422)


def __jwt_validator(priv_jwt: str) -> None:
    """Validates the Authorization header and the JWT."""
    trace_enter(inspect.currentframe())

    parts = priv_jwt.split()

    if parts[0].lower() != 'bearer':
        err_msg = 'Authorization header must start with "Bearer"'
        logger.error(err_msg)
        trace_exit(inspect.currentframe(), err_msg)
        raise ValidationError(err_msg, status_code=422)

    if len(parts) == 1:
        err_msg = 'Token not found'
        logger.error(err_msg)
        trace_exit(inspect.currentframe(), err_msg)
        raise ValidationError(err_msg, status_code=422)

    if len(parts) > 2:
        err_msg = 'Authorization header must be "Bearer token".'
        logger.error(err_msg)
        trace_exit(inspect.currentframe(), err_msg)
        raise ValidationError(err_msg, status_code=422)

    token = parts[1]

    token_parts = token.split('.')

    if len(token_parts) != 3:
        err_msg = 'JWT token does not match format "header.payload.signature".'
        logger.error(err_msg)
        trace_exit(inspect.currentframe(), err_msg)
        raise ValidationError(err_msg, status_code=422)

    b64_header = token_parts[0]
    payload = token_parts[1]

    # TODO: how to validate?
    # signature = token_parts[2]

    try:
        # fix padding required by python base64 module: + '==='
        b64_header = b64_header + '==='

        header = base64.b64decode(b64_header).decode()
        header = json.loads(header)
    except Exception as exc:
        err_msg = f'JWT protected header must be base64 encoded json: {exc}.'
        logger.error(err_msg)
        trace_exit(inspect.currentframe(), err_msg)
        raise ValidationError(err_msg, status_code=422) from exc

    if ('typ' not in header) or ('alg' not in header) or ('kid' not in header):
        err_msg = 'JWT protected header must include "typ", "alg" and "kid".'
        logger.error(err_msg)
        trace_exit(inspect.currentframe(), err_msg)
        raise ValidationError(err_msg, status_code=422)

    try:
        # fix padding required by python base64 module: + '==='
        payload = payload + '==='

        payload = base64.b64decode(payload).decode()
        payload = json.loads(payload)
    except Exception as exc:
        err_msg = f'JWT payload must be base64 encoded json: {exc}.'
        logger.error(err_msg)
        trace_exit(inspect.currentframe(), err_msg)
        raise ValidationError(err_msg, status_code=422) from exc

    if ('sub' not in payload) or ('iss' not in payload) or \
            ('aud' not in payload):
        err_msg = 'JWT payload must include "sub", "iss" & "aud" claim.'
        logger.error(err_msg)
        trace_exit(inspect.currentframe(), err_msg)
        raise ValidationError(err_msg, status_code=422)


VIEW_ARGS = {
    'tenant': fields.Str(
        required=True,
        validate=validate.Length(min=1, max=50)),
    'jwe_kid': fields.Str(
        required=True,
        validate=validate.Length(min=1, max=50))
}

QUERY_ARGS = {
    'requestId': fields.Str(
        required=True,
        validate=__request_id_validator)
}

HEADER_ARGS = {
    'priv_jwt': fields.Str(
        data_key='Authorization',
        required=True,
        validate=__jwt_validator),
    'x-real-ip': fields.Str(
        data_key='X-Real-Ip',
        required=True,
        validate=__x_real_ip_validator),
    'user-agent': fields.Str(
        data_key='user-agent',
        required=True,
        validate=__user_agent_validator)
}
