import os
import base64
import json
import app


class TestIntegrationFlaskApp():
    def test__get_dek_from_vault(self, get_jwt):
        dek = app._get_dek_from_vault(get_jwt, 'salesforce',
                                      'jwe-kid-salesforce-serviceX')
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
