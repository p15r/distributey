import pytest
import app
import config
from werkzeug.datastructures import Headers
import dev.create_jwt


class TestFlaskApp():
    @pytest.fixture(autouse=True)
    def _setup(self):
        self.jwt_token = dev.create_jwt.token

        self.header = Headers([
            ('X-Real-Ip', '172.20.0.1'),
            ('Host', 'up-hyok-wrapper'),
            ('Connection', 'close'),
            ('User-Agent', 'curl/7.68.0'),
            ('Accept', '*/*'),
            ('Authorization', f'Bearer {self.jwt_token}')])

        self.jwt_signing_pubkey = open('dev/tmp/jwt.pub').read()

    def test__get_kid_from_jwt(self):
        assert app._get_kid_from_jwt(self.jwt_token) == 'jwt_kid_salesforce_serviceX'

    def test__get_jwt_from_header(self):
        assert app._get_jwt_from_header(self.header) == self.jwt_token

    def test__decode_jwt(self, monkeypatch):
        monkeypatch.setattr(config, 'CFG_PATH', 'config/config.json')

        assert app._decode_jwt('salesforce', self.jwt_token, self.jwt_signing_pubkey) == \
            ('cacheonlyservice', 'salesforce')

    def test__authenticate(self, monkeypatch):
        monkeypatch.setattr(config, 'CFG_PATH', 'config/config.json')

        assert app._authenticate('salesforce', self.header) == self.jwt_token

    def test_get_wrapped_key(self, http_client):
        # this feels more like an integration test.. wrong place?
        response = http_client.get('/path/to/get/jwe')

        print(response)

        assert False
