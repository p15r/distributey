"""Test module for Flask app."""

import app
import werkzeug
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
            config, '__CFG_PATH', 'config/NONEXISTINGCONFIG.json')

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
