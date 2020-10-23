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

    def test__decode_jwt(self, monkeypatch, get_jwt, get_jwt_signing_pubkey):
        assert app._decode_jwt('salesforce', get_jwt, get_jwt_signing_pubkey) == \
            ('cacheonlyservice', 'salesforce')

    def test__authenticate(self, monkeypatch, get_headers, get_jwt):
        assert app._authenticate('salesforce', get_headers) == get_jwt

    def test_get_wrapped_key_no_auth(self, http_client, monkeypatch):
        # this integration test runs here, because it has no runtime deps
        test_url = '/v1/salesforce/jwe-kid-salesforce-serviceX?resourceId=randomstring'
        test_headers = {'X_REAL_IP': '127.0.0.1'}

        response = http_client.get(test_url, headers=test_headers)

        assert response.status_code == 401
