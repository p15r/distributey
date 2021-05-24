"""
A collection of shared functionality.
"""

import inspect
import jwt
from dy_trace import trace_enter, trace_exit
from dy_logging import logger


def get_kid_from_jwt(priv_token: str) -> str:
    """
    Extracts KID from JWT token. Only use this method after JWT token
    has been validated.
    """
    trace_enter(inspect.currentframe())

    try:
        protected_header_unverified = jwt.get_unverified_header(priv_token)
    except jwt.DecodeError as exc:
        ret = ''
        logger.error('Cannot decode JWT to get kid: %s', exc)
        logger.debug('JWT: %s', priv_token)
        trace_exit(inspect.currentframe(), ret)
        return ret

    ret = protected_header_unverified.get('kid', '')
    trace_exit(inspect.currentframe(), ret)
    return ret
