import app
import config


class TestUnitFlaskApp():
    def test__get_kid_from_jwt(self, get_jwt):
        assert app._get_kid_from_jwt(get_jwt) == 'jwt_kid_salesforce_serviceX'

    def test__get_jwt_from_header(self, get_headers, get_jwt):
        assert app._get_jwt_from_header(get_headers) == get_jwt

    def test__decode_jwt(self, monkeypatch, get_jwt, get_jwt_signing_pubkey):
        monkeypatch.setattr(config, 'CFG_PATH', 'config/config.json')

        assert app._decode_jwt('salesforce', get_jwt, get_jwt_signing_pubkey) == \
            ('cacheonlyservice', 'salesforce')

    def test__authenticate(self, monkeypatch, get_headers, get_jwt):
        monkeypatch.setattr(config, 'CFG_PATH', 'config/config.json')

        assert app._authenticate('salesforce', get_headers) == get_jwt

    def test_get_wrapped_key_no_auth(self, http_client, monkeypatch):
        # integration test runs here, because it has no runtime deps

        monkeypatch.setattr(config, 'CFG_PATH', 'config/config.json')

        test_url = '/v1/salesforce/jwe-kid-salesforce-serviceX?resourceId=randomstring'
        test_headers = {'X_REAL_IP': '127.0.0.1'}

        response = http_client.get(test_url, headers=test_headers)

        assert response.status_code == 401
