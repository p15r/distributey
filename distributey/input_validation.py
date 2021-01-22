import base64
from flask import abort
from webargs import ValidationError
from webargs.flaskparser import parser
from flask import Response
import json
from webargs import fields, validate

from dy_logging import logger


# webargs error handler
@parser.error_handler
def handle_request_parsing_error(
    validation_error, request, schema, error_status_code=None,
        error_headers=None):

    input_data = validation_error.__dict__['data']

    logger.error(
        f'Input validation failed with error "{validation_error}". '
        f'Input: "{input_data}".')

    resp = Response(
        response=json.dumps(validation_error.__dict__['messages']),
        status=422,
        content_type='application/json; ; charset=utf-8')

    abort(resp)


def __x_real_ip_validator(x_real_ip: str) -> None:
    # check min/max length and format

    if not isinstance(x_real_ip, str):
        raise ValidationError(
            '"X-Real-Ip" header is not of type string.', status_code=422)

    if not 6 < len(x_real_ip) < 16:
        raise ValidationError(
            'X-Real-Ip must be between 7 and 15 characters long.',
            status_code=422)

    parts = x_real_ip.split('.')

    if len(parts) != 4:
        raise ValidationError(
            'X-Real-Ip format does not match: digits.digits.digits.digits.',
            status_code=422)

    for part in parts:
        if not 0 < len(part) < 4:
            raise ValidationError(
                'X-Real-Ip format does not match: x.x.x.x-xxx.xxx.xxx.xxx',
                status_code=422)


def jwt_validator(jwt: str) -> None:
    # TODO: log before raising!

    parts = jwt.split()

    if parts[0].lower() != 'bearer':
        raise ValidationError(
            'Authorization header must start with "Bearer"', status_code=422)
    elif len(parts) == 1:
        raise ValidationError('Token not found', status_code=422)
    elif len(parts) > 2:
        raise ValidationError(
            'Authorization header must be "Bearer" token', status_code=422)

    token = parts[1]

    token_parts = token.split('.')

    if len(token_parts) != 3:
        raise ValidationError(
            'JWT token must be of format "header.payload.signature"',
            status_code=422)

    b64_header = token_parts[0]
    payload = token_parts[1]
    signature = token_parts[2]

    try:
        header = base64.b64decode(b64_header).decode()
        header = json.loads(header)
    except Exception as exc:
        raise ValidationError(
            'JWT header must be base64 encoded json.', status_code=422)

    print(header)
    print(type(header))

    if ('typ' not in header) or ('alg' not in header) or ('kid' not in header):
        raise ValidationError(
            'JWT header must include "typ", "alg" and "kid".', status_code=422)

    # fix padding required by python base64 module: + b'==='
    payload = payload + '==='

    try:
        payload = base64.b64decode(payload).decode()
        payload = json.loads(payload)
    except Exception as exc:
        raise ValidationError(
            'JWT payload must be base64 encoded json.', status_code=422)

    if ('sub' not in payload) or ('iss' not in payload) or \
            ('aud' not in payload):
        raise ValidationError(
            'JWT payload must  include "sub", "iss", "aud".', status_code=422)

    # validate "signature"?


# input validation
view_args = {
    'tenant': fields.Str(
        required=True,
        validate=validate.Length(min=1, max=50)),
    'jwe_kid': fields.Str(
        required=True,
        validate=validate.Length(min=1, max=50))
}

query_args = {
    'requestId': fields.Str(
        required=False,
        validate=validate.Length(min=1, max=80))
}

header_args = {
    'jwt': fields.Str(
        data_key='Authorization',
        required=True,
        validate=jwt_validator),
    'x-real-ip': fields.Str(
        data_key='X-Real-Ip',
        required=True,
        validate=__x_real_ip_validator)
}
