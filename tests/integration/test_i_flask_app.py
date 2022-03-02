import os
import datetime
import base64
import json
import jwt
import app


class TestIntegrationFlaskApp():
    def test__get_dek_from_vault(self, get_jwt):
        dek = app._get_dek_from_vault(get_jwt, 'salesforce',
                                      'jwe-kid-salesforce-serviceX')

        assert len(dek) != 0
        assert isinstance(dek, bytearray)

    def test_get_wrapped_key(self, http_client, monkeypatch, get_jwt):
        kid = 'jwe-kid-salesforce-serviceX'
        nonce = os.urandom(16).hex()
        test_url = f'/v1/salesforce/{kid}?requestId={nonce}'
        test_headers = {
            'X_REAL_IP': '127.0.0.1',
            'Authorization': f'Bearer {get_jwt}'}

        resp = http_client.get(test_url, headers=test_headers)
        assert resp.status_code == 200

        json_resp = resp.get_json()
        assert json_resp['kid'] == kid

        b64_protected_header = json_resp['jwe'].split('.')[0]
        protected_header = json.loads(base64.urlsafe_b64decode(
            b64_protected_header))
        assert protected_header['kid'] == kid
        assert protected_header['jti'] == 'randomstring'    # set in app.py

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
            headers=dict(kid='unittest')
        )

        headers = orig_headers.copy()
        headers['Authorization'] = 'Bearer ' + token

        response = http_client.get(get_endpoint_url, headers=headers)

        assert response.status_code == 422
        assert response.json == \
            {'headers':
             {'Authorization':
              ['JWT payload must include "sub", "iss" & "aud" claim.']}}
