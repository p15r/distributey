"""Test module for Flask app."""

import json
import base64
import datetime
import app
import werkzeug
import jwt
import config


class TestUnitFlaskApp():
    """Test class for Flask app."""
    def test__get_kid_from_jwt(self, get_jwt):
        assert app._get_kid_from_jwt(get_jwt) == 'jwt_kid_salesforce_serviceX'

        # test w/ invalid jwt protected header
        split_protected_header = get_jwt.split('.')
        split_protected_header[0] = split_protected_header[0] + 'badstring'
        bad_jwt = '.'.join(split_protected_header)

        kid = app._get_kid_from_jwt(bad_jwt)

        if kid:
            assert False, ('Should fail if protected header is malformed.'
                           f'Got kid "{kid}".')
        else:
            assert True, 'Failed as expected on malformed protected header.'

    def test__get_jwt_from_header(self, get_headers, get_jwt):
        assert app._get_jwt_from_header('Bearer ' + get_jwt) == get_jwt

        # test w/ headers w/o bearer token
        assert app._get_jwt_from_header(get_jwt) == ''

    def test__decode_jwt(self, get_jwt, get_jwt_signing_pubkey):
        assert app._decode_jwt(
            'salesforce', get_jwt, get_jwt_signing_pubkey) == \
            ('cacheonlyservice', 'salesforce')

        # test w/ non existing tenant
        try:
            app._decode_jwt(
                'nonexistingtenant', get_jwt, get_jwt_signing_pubkey)
            assert False, 'Should fail if non existing tenant is given.'
        except werkzeug.exceptions.HTTPException:
            assert True, 'Failed as expected on non existing tenant.'

        # test w/ expired token
        old_token = ('eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZC'
                     'I6Imp3dF9raWRfc2FsZXNmb3JjZV9zZXJ2aWNlWCJ9.eyJzdW'
                     'IiOiJjYWNoZW9ubHlzZXJ2aWNlIiwiaXNzIjoic2FsZXNmb3J'
                     'jZSIsImF1ZCI6InVybjpoeW9rLXdyYXBwZXIiLCJpYXQiOjE2'
                     'MDM2NTE2MTMsImV4cCI6MTYwMzY1MTkxM30.NBhBFYLm4ySZq'
                     'Dk5sYJtv0NY56Ti3SgB6BrO1iE7tdOBMmjM6BSNQDaRBscURw'
                     'ZuQWNM2f2Leab4Kgf1wax5O9KrRJpD6Ym4jBH2xTHtgzxLfUF'
                     'kEihyVEpLes0Nf2e-w0efOq5Ayqmo_KfmlTqP1PK37U9CaIub'
                     'yqKYOSFAbclQ4rEkiZOM38--iJbd6syJ6W0nnEUvgRaQichZK'
                     '3mN3Gdo46C-WUY21MPOy_6qz4WGu6qCAEjBePmt_-3dOpPKQR'
                     '0CGCKTtCP8psga3M6W9WUgaCpgYnDS-YQdEnD3VG575J-1Cmd'
                     'cShKc-Fo2F-FWpybcP98hMaFg2sQfgjgFNg')

        assert app._decode_jwt(
            'salesforce', old_token, get_jwt_signing_pubkey) == ('', '')

    def test___authenticate(self, get_headers, get_jwt):
        assert app._authenticate('salesforce', 'Bearer ' + get_jwt) == get_jwt

    def test_get_wrapped_key_no_auth(
            self, http_client, get_jwt, get_endpoint_url,
            get_endpoint_url_nonexistingtenant):
        # this integration test runs here, because it has no runtime deps
        headers = {'X_REAL_IP': '127.0.0.1'}

        # access API w/o Authorization header
        response = http_client.get(get_endpoint_url, headers=headers)
        assert response.status_code == 422

        # access API w/ wrong tenant
        response = http_client.get(
            get_endpoint_url_nonexistingtenant, headers=headers)
        assert response.status_code == 422

        # further coverage requires Vault, thus covered w/ integration tests

    def test_get_healthz(self, monkeypatch, http_client):
        endpoint = '/v1/healthz'
        headers = {'X_REAL_IP': '127.0.0.1'}

        response = http_client.get(endpoint, headers=headers)
        assert response.status_code == 200

        # test w/o available config file
        monkeypatch.setattr(
            config, 'CFG_PATH', 'config/NONEXISTINGCONFIG.json')

        response = http_client.get(endpoint, headers=headers)
        assert response.status_code == 500

    def test___user_agent_validator(
            self, http_client, get_endpoint_url, get_headers):
        """
        Issues invalid HTTP request and validates response.
        This test also covers "__handle_request_parsing_error()".
        """

        # set invalid UA to trigger error
        headers = get_headers
        headers['User-Agent'] = 'NoValueAfterSlash/'

        response = http_client.get(get_endpoint_url, headers=headers)

        assert response.status_code == 422
        assert response.json == \
            {'headers':
             {'user-agent':
              ['User agent pattern does not match "name/version"']}}
        assert response.mimetype == 'application/json'
        assert response.charset == 'utf-8'

    def test___x_real_ip_validator(
            self, http_client, get_endpoint_url, get_headers):
        headers = get_headers
        headers['X-Real-Ip'] = '1'

        response = http_client.get(get_endpoint_url, headers=headers)

        assert response.status_code == 422
        assert response.json == \
            {'headers':
             {'X-Real-Ip':
              ['X-Real-Ip must be between 7 and 15 characters long.']}}

        headers['X-Real-Ip'] = '012345678'

        response = http_client.get(get_endpoint_url, headers=headers)

        assert response.status_code == 422
        assert response.json == \
            {'headers':
             {'X-Real-Ip':
              ['X-Real-Ip format does not match: '
               'digits.digits.digits.digits.']}}

        headers['X-Real-Ip'] = '127.0.0.1111'
        response = http_client.get(get_endpoint_url, headers=headers)

        assert response.status_code == 422
        assert response.json == \
            {'headers':
             {'X-Real-Ip':
              ['X-Real-Ip format does not match: x.x.x.x-xxx.xxx.xxx.xxx']}}

    def test___jwt_validator(
            self, http_client, get_endpoint_url, get_headers, get_jwt):
        headers = get_headers
        orig_headers = headers.copy()

        # test with a valid jwt + auth header
        response = http_client.get(get_endpoint_url, headers=headers)

        assert response.status_code == 200
        assert response.json['kid'] == 'jwe-kid-salesforce-serviceX'
        assert isinstance(response.json['jwe'], str)

        # test with invalid auth header:
        # remove "Bearer" string from auth header
        headers['Authorization'] = headers['Authorization'].split(' ')[1]

        response = http_client.get(get_endpoint_url, headers=headers)

        assert response.status_code == 422
        assert response.json == \
            {'headers':
             {'Authorization':
              ['Authorization header must start with "Bearer"']}}

        # test with invalid auth header: remove jwt
        headers['Authorization'] = 'Bearer '

        response = http_client.get(get_endpoint_url, headers=headers)

        assert response.status_code == 422
        assert response.json == \
            {'headers': {'Authorization': ['Token not found']}}

        # test with invalid auth header: auth header too long
        headers = orig_headers.copy()
        headers['Authorization'] = headers['Authorization'] + ' SOMETHING'

        response = http_client.get(get_endpoint_url, headers=headers)

        assert response.status_code == 422
        assert response.json == \
            {'headers':
             {'Authorization':
              ['Authorization header must be "Bearer token".']}}

        # test with invalid jwt: no signature
        # get jwt protected header
        headers = orig_headers.copy()
        b64_jwt = headers['Authorization'].split(' ')[1]
        modified_b64_jwt = b64_jwt.split('.')[0:1]  # pos 2 would be sign.

        # add modified jwt to auth header
        headers = orig_headers.copy()
        headers['Authorization'] = 'Bearer ' + '.'.join(modified_b64_jwt)

        response = http_client.get(get_endpoint_url, headers=headers)

        assert response.status_code == 422
        assert response.json == \
            {'headers':
             {'Authorization':
              ['JWT token does not match format "header.payload.signature".']}}

        # test with invalid jwt: required field missing in protected header
        # get jwt protected header
        headers = orig_headers.copy()
        b64_jwt = headers['Authorization'].split(' ')[1]
        b64_protected_header = b64_jwt.split('.')[0]
        protected_header = json.loads(
            base64.urlsafe_b64decode(b64_protected_header))

        # remove kid from protected header
        del protected_header['kid']

        # add modified protected header to initial jwt
        modified_b64_protected_header = base64.urlsafe_b64encode(
            json.dumps(protected_header).encode())
        b64_jwt = b64_jwt.split('.')
        b64_jwt[0] = modified_b64_protected_header.decode()
        b64_jwt = '.'.join(b64_jwt)

        # set b64_jwt as new Bearer token in header
        headers = get_headers
        headers['Authorization'] = 'Bearer ' + b64_jwt

        response = http_client.get(get_endpoint_url, headers=headers)

        assert response.status_code == 422
        assert response.json == \
            {'headers':
             {'Authorization':
              ['JWT protected header must include "typ", "alg" and "kid".']}}

        # test with invalid jwt: missing sub claim

        expiration_time = 300
        payload = {
            # 'sub': sub,
            'iss': 'unittest',
            'aud': 'urn:distributey',
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(
                seconds=expiration_time)
        }

        with open('dev/tmp/jwt.key') as file:
            private_key = file.read()

        token = jwt.encode(
            payload, private_key, algorithm='RS256',
            headers=dict(kid='unittest'))
        token = token.decode('utf-8')

        headers = orig_headers.copy()
        headers['Authorization'] = 'Bearer ' + token

        response = http_client.get(get_endpoint_url, headers=headers)

        assert response.status_code == 422
        assert response.json == \
            {'headers':
             {'Authorization':
              ['JWT payload must include "sub", "iss" & "aud" claim.']}}
