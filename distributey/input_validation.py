import base64
from flask import abort
from webargs import ValidationError
from webargs.flaskparser import parser
from flask import Response
import json
from webargs import fields, validate

from dy_logging import logger

# TODO: type hinting

# webargs error handler
@parser.error_handler
def __handle_request_parsing_error(
    validation_error, request, schema, error_status_code=None,
        error_headers=None):

    input_data = validation_error.__dict__['data']

    logger.error(
        f'Input validation failed with error "{validation_error}". '
        f'Input: "{input_data}".')

    resp = Response(
        response=json.dumps(validation_error.__dict__['messages']),
        status=422,
        content_type='application/json; charset=utf-8')

    abort(resp)


# various webargs validators
def __user_agent_validator(user_agent: str) -> None:
    """
    User agent specs: https://developer.mozilla.org/en-US/docs/Web/
        HTTP/Headers/User-Agent

    Enforce a minimum pattern of "uname/version".
    """

    if len(user_agent) > 150:
        err_msg = 'User agent contains more than 150 characters.'
        logger.error(err_msg)
        raise ValidationError(err_msg, status_code=422)

    parts = user_agent.split('/')

    if (len(parts) < 2) or (len(parts[0]) < 1) or (len(parts[1]) < 1):
        err_msg = 'User agent pattern does not match "name/version"'
        logger.error(err_msg)
        raise ValidationError(err_msg, status_code=422)


def __x_real_ip_validator(x_real_ip: str) -> None:
    if not 6 < len(x_real_ip) < 16:
        err_msg = 'X-Real-Ip must be between 7 and 15 characters long.'
        raise ValidationError(err_msg, status_code=422)

    parts = x_real_ip.split('.')

    if len(parts) != 4:
        err_msg = ('X-Real-Ip format does not match: '
                   'digits.digits.digits.digits.')
        logger.error(err_msg)
        raise ValidationError(err_msg, status_code=422)

    for part in parts:
        if not 0 < len(part) < 4:
            err_msg = ('X-Real-Ip format does not match: '
                       'x.x.x.x-xxx.xxx.xxx.xxx')
            logger.error(err_msg)
            raise ValidationError(err_msg, status_code=422)


def __jwt_validator(jwt: str) -> None:
    parts = jwt.split()

    if parts[0].lower() != 'bearer':
        err_msg = 'Authorization header must start with "Bearer"'
        logger.error(err_msg)
        raise ValidationError(err_msg, status_code=422)
    elif len(parts) == 1:
        err_msg = 'Token not found'
        logger.error(err_msg)
        raise ValidationError(err_msg, status_code=422)
    elif len(parts) > 2:
        err_msg = 'Authorization header must be "Bearer token".'
        logger.error(err_msg)
        raise ValidationError(err_msg, status_code=422)

    token = parts[1]

    token_parts = token.split('.')

    if len(token_parts) != 3:
        err_msg = 'JWT token must match "header.payload.signature"'
        logger.error(err_msg)
        raise ValidationError(err_msg, status_code=422)

    b64_header = token_parts[0]
    payload = token_parts[1]

    # TODO: how to validate?
    # signature = token_parts[2]

    try:
        header = base64.b64decode(b64_header).decode()
        header = json.loads(header)
    except Exception as exc:
        err_msg = 'JWT header must be base64 encoded json.'
        logger.error(err_msg)
        raise ValidationError(err_msg, status_code=422)

    if ('typ' not in header) or ('alg' not in header) or ('kid' not in header):
        err_msg = 'JWT header must include "typ", "alg" and "kid".'
        logger.error(err_msg)
        raise ValidationError(err_msg, status_code=422)

    # fix padding required by python base64 module: + '==='
    payload = payload + '==='

    try:
        payload = base64.b64decode(payload).decode()
        payload = json.loads(payload)
    except Exception as exc:
        err_msg = 'JWT payload must be base64 encoded json.'
        logger.error(err_msg)
        raise ValidationError(err_msg, status_code=422)

    if ('sub' not in payload) or ('iss' not in payload) or \
            ('aud' not in payload):
        err_msg = 'JWT payload must include "sub", "iss" & "aud" claim.'
        logger.error(err_msg)
        raise ValidationError(err_msg, status_code=422)


# input validation
_view_args = {
    'tenant': fields.Str(
        required=True,
        validate=validate.Length(min=1, max=50)),
    'jwe_kid': fields.Str(
        required=True,
        validate=validate.Length(min=1, max=50))
}

_query_args = {
    'requestId': fields.Str(
        required=False,
        validate=validate.Length(min=1, max=80))
}

_header_args = {
    'jwt': fields.Str(
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
