import config
import base64
import json


class TestIntegrationFlaskApp():
    def test_get_wrapped_key(self, http_client, monkeypatch, get_jwt):
        # this feels more like an integration test.. wrong place?

        monkeypatch.setattr(config, 'CFG_PATH', 'config/config.json')

        kid = 'jwe-kid-salesforce-serviceX'
        nonce = 'randomstring'
        test_url = f'/v1/salesforce/{kid}?requestId={nonce}'
        test_headers = {'X_REAL_IP': '127.0.0.1', 'Authorization': f'Bearer {get_jwt}'}

        resp = http_client.get(test_url, headers=test_headers)
        assert resp.status_code == 200

        json_resp = resp.get_json()
        assert json_resp['kid'] == kid

        b64_protected_header = json_resp['jwe'].split('.')[0]
        protected_header = json.loads(base64.urlsafe_b64decode(b64_protected_header))
        assert protected_header['kid'] == kid
        assert protected_header['jti'] == nonce
