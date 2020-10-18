import pytest
import app
import config
from werkzeug.datastructures import Headers


class TestFlaskApp():
    @pytest.fixture(autouse=True)
    def _setup(self):
        self.jwt_token = (
            b'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imp3dF9'
            b'raWRfc2FsZXNmb3JjZV9zZXJ2aWNlWCJ9.eyJzdWIiOiJjYWNoZW9ubHlzZXJ2aWNlIiw'
            b'iaXNzIjoic2FsZXNmb3JjZSIsImF1ZCI6InVybjpoeW9rLXdyYXBwZXIiLCJpYXQiOjE2'
            b'MDMwMzkxNjcsImV4cCI6MTYwMzAzOTQ2N30.DAeIzXLkkTWWEL0y60isUvLwHK-Iw_MNU'
            b'4q7LJkLn20OrxrDhnfolU8BknEWqCP5z5LeT3DJwkRP5p75WuUJ8GTLAglL3jtGHEL4Pa'
            b'7NNrKdJCMXsRRlMgXZfLfxnXpSAJo4L24v8kAePIOIxqM8EtShmh5-XvV-QQmcVe9VG6u'
            b'eOhPneBJi50aAEEjjOlNXzfjPWS-xCjwDpU_SnMEZK3Zjf0dFGWEMxm3pwIKRsgrCwKZP'
            b'H_2u-8G9Ds48C29wKoZ6IFGnqFk7dioGfPfRICaUi8jHWV1k2L-Rz70RatSHLMKnk-WMh'
            b'mNkRFIFjn5v4d0luFyi3zRrpXq28hY_BQ')

        self.header = Headers([
            ('X-Real-Ip', '172.20.0.1'),
            ('Host', 'up-hyok-wrapper'),
            ('Connection', 'close'),
            ('User-Agent', 'curl/7.68.0'),
            ('Accept', '*/*'),
            ('Authorization', f'Bearer {self.jwt_token.decode()}')])

        self.jwt_signing_pubkey = open('dev/tmp/jwt.pub').read()

    def test__get_kid_from_jwt(self):
        assert app._get_kid_from_jwt(self.jwt_token) == 'jwt_kid_salesforce_serviceX'

    def test__get_jwt_from_header(self):
        assert app._get_jwt_from_header(self.header) == self.jwt_token.decode()

    def test__decode_jwt(self, monkeypatch):
        monkeypatch.setattr(config, 'CFG_PATH', 'config/config.json')

        assert app._decode_jwt('salesforce', self.jwt_token, self.jwt_signing_pubkey, verify_exp=False) == \
            ('cacheonlyservice', 'salesforce')

    def test__authenticate(self):
        assert False
