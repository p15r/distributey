import json
import base64
import app


class TestUnitFlaskApp():
    def test__get_kid_from_jwt(self, get_jwt):
        assert app._get_kid_from_jwt(get_jwt) == 'jwt_kid_salesforce_serviceX'

        # test w/ invalid jwt protected header
        split_protected_header = get_jwt.split('.')
        split_protected_header[0] = split_protected_header[0] + 'badstring'
        bad_jwt = '.'.join(split_protected_header)

        kid = app._get_kid_from_jwt(bad_jwt)

        if kid:
            assert False, f'Should fail if protected header is malformed. Got kid "{kid}".'
        else:
            assert True, 'Failed as expected on malformed protected header.'

    def test__get_jwt_from_header(self, get_headers, get_jwt):
        assert app._get_jwt_from_header(get_headers) == get_jwt

        # test w/ headers w/o bearer token
        headers = get_headers
        headers['Authorization'] = 'no bearer here'
        assert app._get_jwt_from_header(headers) == ''

    def test__decode_jwt(self, monkeypatch, get_jwt, get_jwt_signing_pubkey):
        assert app._decode_jwt('salesforce', get_jwt, get_jwt_signing_pubkey) == \
            ('cacheonlyservice', 'salesforce')

    def test__authenticate(self, monkeypatch, get_headers, get_jwt):
        assert app._authenticate('salesforce', get_headers) == get_jwt

        # test jwt w/o kid
        # get jwt protected header
        b64_jwt = get_headers['Authorization'].split(' ')[1]
        b64_protected_header = b64_jwt.split('.')[0]
        protected_header = json.loads(base64.urlsafe_b64decode(b64_protected_header))

        # remove kid from protected header
        del protected_header['kid']

        # add modified protected header to initial jwt
        modified_b64_protected_header = base64.urlsafe_b64encode(json.dumps(protected_header).encode())
        b64_jwt = b64_jwt.split('.')
        b64_jwt[0] = modified_b64_protected_header.decode()
        b64_jwt = '.'.join(b64_jwt)

        # set b64_jwt as new Bearer token in header
        headers = get_headers
        headers['Authorization'] = 'Bearer ' + b64_jwt

        if app._authenticate('salesforce', headers) == '':
            assert True, 'Failed as expected w/ missing kid in JWT protected header.'
        else:
            assert False, 'Should fail if kid in missing in JWT protected header.'

    def test_get_wrapped_key_no_auth(self, http_client, monkeypatch, get_jwt):
        # this integration test runs here, because it has no runtime deps
        endpoint = '/v1/salesforce/jwe-kid-salesforce-serviceX?resourceId=randomstring'
        headers = {'X_REAL_IP': '127.0.0.1'}

        # access API w/o Authorization header
        response = http_client.get(endpoint, headers=headers)
        assert response.status_code == 401

        # access API w/ wrong tenant
        endpoint_nonexisting_tenant = '/v1/nontexistingtenant/jwe-kid-salesforce-serviceX?resourceId=randomstring'
        response = http_client.get(endpoint_nonexisting_tenant, headers=headers)
        assert response.status_code == 401

        # further coverage requires Vault, thus covered w/ integration tests
