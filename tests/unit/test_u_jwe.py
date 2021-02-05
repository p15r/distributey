"""Tests module jwe.py."""

import base64
import json
import jwe


class TestJwe():
    """Tests module jwe.py."""
    def test__get_key_consumer_cert(self):
        key_consumer_cert = jwe._get_key_consumer_cert('salesforce', 'jwe-kid-salesforce-serviceX')
        assert isinstance(key_consumer_cert, str)
        if isinstance(key_consumer_cert, str) and key_consumer_cert.startswith('-----BEGIN CERTIFICATE-----'):
            assert True, 'Looks like a legitimate certificate.'
        else:
            assert False, 'Cannot detect certificate.'

        assert jwe._get_key_consumer_cert(
            'nonexistingtenant', 'jwe-kid-salesforce-serviceX') == ''

    def test__encrypt_cek_with_key_consumer_key(self):
        b64_cek_ciphertext = jwe._encrypt_cek_with_key_consumer_key(
            'salesforce', 'jwe-kid-salesforce-serviceX', b'randrom-cek')
        assert isinstance(b64_cek_ciphertext, bytes)
        try:
            decoded_ciphertext = base64.urlsafe_b64decode(b64_cek_ciphertext)
            assert True, 'Successfully base64 decoded cek ciphertext.'
            assert isinstance(decoded_ciphertext, bytes)
        except Exception as e:
            assert False, e

        assert jwe._encrypt_cek_with_key_consumer_key(
            'nonexistingtenant', 'jwe-kid-salesforce-serviceX',
            'randrom-cek') == b''

    def test__encrypt_dek_with_cek(self, get_protected_headers):
        b64_dek_ciphertext, b64_tag = jwe._encrypt_dek_with_cek(
            b'16bitrandom12345', b'randomiv', b'randomdek', get_protected_headers)

        assert isinstance(b64_dek_ciphertext, bytes)
        assert isinstance(b64_tag, bytes)
        try:
            decoded_ciphertext = base64.urlsafe_b64decode(b64_dek_ciphertext)
            assert True, 'Successfully base64 decoded cek ciphertext.'
            assert isinstance(decoded_ciphertext, bytes)
        except Exception as e:
            assert False, e

    def test__create_jwe_token_json(self, get_protected_headers):
        json_jwe_token = jwe._create_jwe_token_json(
            'jwe-kid-salesforce-serviceX',
            get_protected_headers,
            base64.urlsafe_b64encode(b'cek-ciphertext'),
            base64.urlsafe_b64encode(b'iv'),
            base64.urlsafe_b64encode(b'dek-ciphertext'),
            base64.urlsafe_b64encode(b'tag')
            )

        assert json.loads(json_jwe_token)['kid'] == 'jwe-kid-salesforce-serviceX'
        assert json.loads(json_jwe_token)['jwe']
        protected_header = base64.urlsafe_b64decode(json.loads(json_jwe_token)['jwe'].split('.')[0])
        assert json.loads(protected_header)['kid'] == 'jwe-kid-salesforce-serviceX'
        assert json.loads(protected_header)['jti'] == 'nonce'

    def test__get_jwe_protected_header(self):
        nonce = 'random-nonce'
        jwe_kid = 'jwe-kid-salesforce-serviceX'
        b64_protected_header = jwe._get_jwe_protected_header(jwe_kid, nonce)
        protected_header = json.loads(base64.urlsafe_b64decode(b64_protected_header))
        assert protected_header['kid'] == jwe_kid
        assert protected_header['jti'] == nonce
