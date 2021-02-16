"""Tests module input_validation."""

import pytest
from webargs import ValidationError
import input_validation


def test___request_id_validator():
    # test w/ too short requestid/nonce
    with pytest.raises(ValidationError):
        input_validation.__request_id_validator('notlongenough')

    # test w/ non-alphanummeric chars
    with pytest.raises(ValidationError):
        input_validation.__request_id_validator(
            '1234567890123456789012345678901-')


def test____user_agent_validator():
    # test w/ too long user-agent
    ua = 'x' * 151
    with pytest.raises(ValidationError):
        input_validation.__user_agent_validator(ua)

    # test w/ wrong format
    with pytest.raises(ValidationError):
        input_validation.__user_agent_validator('noslash')


def test____jwt_validator():
    with pytest.raises(ValidationError):
        input_validation.__jwt_validator('no bearer at start')
