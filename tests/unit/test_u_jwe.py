"""Tests module jwe.py."""

import base64
import os
from stat import S_IRGRP, S_IROTH, S_IRUSR
import json
import config
import jwe


class TestJwe():
    """Tests module jwe.py."""
    def test_get_wrapped_key_as_jwe(self, monkeypatch, get_jwt):
        nonce = '12345678901234567890123456789012'
        jwe_kid = 'jwe-kid-salesforce-serviceX'

        def mock_devmode(*args):
            if args[0] == 'DEV_MODE':
                return True
            else:
                cert = ('config/backend/distributey_serviceX_key_consumer.crt')
                return cert

        monkeypatch.setattr(config, 'get_config_by_keypath', mock_devmode)

        jwe_token = jwe.get_wrapped_key_as_jwe(bytearray('randomdek'.encode()),
                                               'salesforce', jwe_kid, nonce)
        assert json.loads(jwe_token)['kid'] == jwe_kid

    def test_get_wrapped_key_as_jwe_2(self, monkeypatch, get_jwt):
        nonce = '12345678901234567890123456789013'
        jwe_kid = 'jwe-kid-salesforce-serviceX'

        def mock_false(*args):
            return False

        monkeypatch.setattr(jwe, '_encrypt_cek_with_key_consumer_key',
                            mock_false)

        jwe_token = jwe.get_wrapped_key_as_jwe(bytearray('randomdek'.encode()),
                                               'salesforce', jwe_kid, nonce)

        assert jwe_token == ''

    def test_get_wrapped_key_as_jwe_3(self, monkeypatch, get_jwt):
        nonce = '12345678901234567890123456789014'
        jwe_kid = 'jwe-kid-salesforce-serviceX'

        def mock_false(*args):
            return False

        monkeypatch.setattr(jwe, '_get_jwe_protected_header',
                            mock_false)

        jwe_token = jwe.get_wrapped_key_as_jwe(bytearray('randomdek'.encode()),
                                               'salesforce', jwe_kid, nonce)

        assert jwe_token == ''

    def test_get_wrapped_key_as_jwe_4(self, monkeypatch, get_jwt):
        nonce = '12345678901234567890123456789015'
        jwe_kid = 'jwe-kid-salesforce-serviceX'

        def mock_false(*args):
            return ('', '')

        monkeypatch.setattr(jwe, '_encrypt_dek_with_cek',
                            mock_false)

        jwe_token = jwe.get_wrapped_key_as_jwe(bytearray('randomdek'.encode()),
                                               'salesforce', jwe_kid, nonce)

        assert jwe_token == ''

    def test_get_wrapped_key_as_jwe_5(self, monkeypatch, get_jwt):
        nonce = '12345678901234567890123456789014'
        jwe_kid = 'jwe-kid-salesforce-serviceX'

        def mock_false(*args):
            return ''

        monkeypatch.setattr(jwe, '_create_jwe_token_json',
                            mock_false)

        jwe_token = jwe.get_wrapped_key_as_jwe(bytearray('randomdek'.encode()),
                                               'salesforce', jwe_kid, nonce)

        assert jwe_token == ''

    def test__get_key_consumer_cert(self, capfd):
        # receive dedicated key consumer cert by tenant & jwe id
        key_consumer_cert = jwe._get_key_consumer_cert(
            'salesforce', 'jwe-kid-salesforce-serviceX')
        assert isinstance(key_consumer_cert, str)
        if isinstance(key_consumer_cert, str) and \
                key_consumer_cert.startswith('-----BEGIN CERTIFICATE-----'):
            assert True, 'Looks like a legitimate certificate.'
        else:
            assert False, 'Cannot detect certificate.'

        assert jwe._get_key_consumer_cert(
            'nonexistingtenant', 'jwe-kid-salesforce-serviceX') == ''

        # test w/ missing fs perm
        key_consumer_cert_path = \
            config.get_key_consumer_cert(
                'salesforce', 'jwe-kid-salesforce-serviceX')

        os.chmod(key_consumer_cert_path, S_IROTH)     # remove read perms

        jwe._get_key_consumer_cert('salesforce', 'jwe-kid-salesforce-serviceX')
        out, err = capfd.readouterr()

        pos = err.find('[Errno 13] Permission denied: \'config/backend/'
                       'distributey_serviceX_key_consumer.crt\'.')
        assert pos > -1     # if pos > -1, the string has been found

        # restore read perms
        os.chmod(key_consumer_cert_path, S_IRUSR | S_IRGRP)

        # receive backend-wide key consumer cert by tenant
        key_consumer_cert = jwe._get_key_consumer_cert(
            'salesforce', 'non-existing-jwe')

        assert key_consumer_cert == ''

        key_consumer_cert = jwe._get_key_consumer_cert(
            'salesforce-dev', 'non-existing-jwe')

        assert key_consumer_cert.startswith('-----BEGIN CERTIFICATE-----')

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

    def test__encrypt_dek_with_cek(self, monkeypatch, get_protected_headers):
        def mock_devmode(*args):
            # if get_config_by_keypath() is called with key DEV_MODE,
            # interfere and return true, if called with other keys, ignore
            if args[0] == 'DEV_MODE':
                return True

        monkeypatch.setattr(config, 'get_config_by_keypath', mock_devmode)

        b64_dek_ciphertext, b64_tag = jwe._encrypt_dek_with_cek(
            b'16bitrandom12345', b'randomiv', b'randomdek',
            get_protected_headers)

        assert isinstance(b64_dek_ciphertext, bytes)
        assert isinstance(b64_tag, bytes)
        try:
            decoded_ciphertext = base64.urlsafe_b64decode(b64_dek_ciphertext)
            assert True, 'Successfully base64 decoded cek ciphertext.'
            assert isinstance(decoded_ciphertext, bytes)
        except Exception as e:
            assert False, e

    def test__create_jwe_token_json(self, monkeypatch, get_protected_headers):
        json_jwe_token = jwe._create_jwe_token_json(
            'jwe-kid-salesforce-serviceX',
            get_protected_headers,
            base64.urlsafe_b64encode(b'cek-ciphertext'),
            base64.urlsafe_b64encode(b'iv'),
            base64.urlsafe_b64encode(b'dek-ciphertext'),
            base64.urlsafe_b64encode(b'tag')
            )

        assert json.loads(json_jwe_token)['kid'] == \
            'jwe-kid-salesforce-serviceX'
        assert json.loads(json_jwe_token)['jwe']
        protected_header = base64.urlsafe_b64decode(
            json.loads(json_jwe_token)['jwe'].split('.')[0])
        assert json.loads(protected_header)['kid'] == \
            'jwe-kid-salesforce-serviceX'
        assert json.loads(protected_header)['jti'] == 'nonce'

        # trigger exc
        def mock_json(*args):
            raise Exception('testing')

        monkeypatch.setattr(json, 'dumps', mock_json)

        json_jwe_token = jwe._create_jwe_token_json(
            'jwe-kid-salesforce-serviceX',
            get_protected_headers,
            base64.urlsafe_b64encode(b'cek-ciphertext'),
            base64.urlsafe_b64encode(b'iv'),
            base64.urlsafe_b64encode(b'dek-ciphertext'),
            base64.urlsafe_b64encode(b'tag')
            )

        assert json_jwe_token == ''

    def test__get_jwe_protected_header(self, monkeypatch):
        nonce = 'random-nonce'
        jwe_kid = 'jwe-kid-salesforce-serviceX'
        b64_protected_header = jwe._get_jwe_protected_header(jwe_kid, nonce)
        protected_header = json.loads(base64.urlsafe_b64decode(
            b64_protected_header))
        assert protected_header['kid'] == jwe_kid
        assert protected_header['jti'] == nonce

        # trigger exc
        def mock_json(*args):
            raise Exception('testing')

        monkeypatch.setattr(json, 'dumps', mock_json)

        b64_protected_header = jwe._get_jwe_protected_header(jwe_kid, nonce)

        assert b64_protected_header == b''
