"""Tests module input_validation."""

import base64
import json
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


def test____jwt_validator(get_jwt):
    with pytest.raises(ValidationError):
        input_validation.__jwt_validator('no bearer at start')

    with pytest.raises(ValidationError):
        input_validation.__jwt_validator('Bearer')

    with pytest.raises(ValidationError):
        input_validation.__jwt_validator('Bearer 1 2')

    with pytest.raises(ValidationError):
        input_validation.__jwt_validator('Bearer token.token.token.token')

    with pytest.raises(ValidationError):
        input_validation.__jwt_validator('Bearer token.token.token')

    # test w/ JWT protected header w/o 'typ' field
    jwt = get_jwt
    b64_protected_header = jwt.split('.')[0]
    protected_header = base64.b64decode(b64_protected_header)
    protected_header = json.loads(protected_header)
    del protected_header['typ']
    protected_header = json.dumps(protected_header)
    b64_protected_header = base64.b64encode(protected_header.encode()).decode()

    jwt_parts = jwt.split('.')
    jwt_parts[0] = b64_protected_header

    mangled_jwt = '.'.join(jwt_parts)

    with pytest.raises(ValidationError):
        input_validation.__jwt_validator('Bearer ' + mangled_jwt)

    # test w/ JWT incorrect payload

    jwt = get_jwt
    jwt_parts = jwt.split('.')
    jwt_parts[1] = jwt_parts[1] + 'xxx'

    mangled_jwt = '.'.join(jwt_parts)

    with pytest.raises(ValidationError):
        input_validation.__jwt_validator('Bearer ' + mangled_jwt)

    # test w/ JWT w/o iss claim
    missing_iss_token = ('eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6I'
                         'mp3dF9raWRfc2FsZXNmb3JjZV9zZXJ2aWNlWCJ9.eyJzd'
                         'WIiOiJXUk9OR1NVQiIsImF1ZCI6InVybjpkaXN0cmlidX'
                         'RleSIsImlhdCI6MTYxMzUwNDgxNSwiZXhwIjozMzExNzk'
                         '2ODgxNX0.oMwB-LvPIfOd8JPj5QPwk0SpqD8RNYW9Fe3i'
                         'lnZ-XUICd7qX0k6KrxE_6Cq5Nm9tvJ2Oe32snt9tgVUcY'
                         'ajdKRXEc1B7cLO_HZwleAV9byOvGNZbTBxj3i_xBZvGBF'
                         '-Q-M_mWzLW_F9EY34HWdYY6PiHXNrZHgprOfCrwxSPi1z'
                         'ZvGGZun-3WKX6u1gItHqMzxjcL7jFO4hVpVhxUNbhpUjD'
                         'INxzxzHFhwFWTkaAd8KKvUFXYasVo0fpsMbu_hUEbLCaU'
                         'M_955i9zJnLNAolElDPh8yV65dHoEEVVcWKaF1czYYfjP'
                         'px10I3J2UhxklaG3D3feIbKJq4pA1Zob6XrzfTNqdVvE-'
                         'jCKGEuBb5IJXeFejYBYDB-99C16jOP3As9WDoVlE-Eksm'
                         'gDHmPdapfwzavfbRoFHJnfzN22evLus8C05VmEFT6ao6V'
                         '8eMlWtnII22O5GDxby6KdaFyMIxoxbUClZ49d88lcIspk'
                         'Rb-qzApK2W_MUTqm5y4cS8VPVWe9BNnUulEkrnuWPVJvS'
                         '-MMveelSHX0dMAxaGRQHjZt52asZKBzEBk-D-0lyKTxJ-'
                         'CgbUbcsPC-Nw7HD4ldI7-WyQznoFk9RW41BPXRLHgb9Ts'
                         'tDZNIURpwdOnVoflD7deeX_eqkhuP1_-p28bk-Xt9JPvT'
                         'JkMZqtvYjHKKq9Bfg')

    with pytest.raises(ValidationError):
        input_validation.__jwt_validator('Bearer ' + missing_iss_token)
