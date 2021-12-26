"""Testing for vault_backend module."""

import hvac
import pytest
import requests
import config
import vault_backend


def test___get_vault_client(monkeypatch):
    # valid test
    client = vault_backend.__get_vault_client('salesforce')
    assert isinstance(client, hvac.Client)

    # test w/ no VAULT_CERT
    def mock_vault_cert(*args):
        return False

    monkeypatch.setattr(config, 'get_vault_ca_cert', mock_vault_cert)
    client = vault_backend.__get_vault_client('salesforce')
    assert isinstance(client, hvac.Client)


def test_get_dynamic_secret(monkeypatch, get_jwt):
    # test w/o connection to vault
    dek = vault_backend.get_dynamic_secret('salesforce', 'salesforce',
                                           'latest', get_jwt)

    assert dek == b''

    # test w/ failing client creation
    def mock_client(tenant: str):
        return None

    monkeypatch.setattr(vault_backend, '__get_vault_client', mock_client)

    dek = vault_backend.get_dynamic_secret('salesforce', 'salesforce',
                                           'latest', get_jwt)


def test_get_dynamic_secret_3(monkeypatch, get_jwt):
    # test client initialized
    def mock_auth_client(*args):
        return vault_backend.__get_vault_client('salesforce')

    monkeypatch.setattr(vault_backend, '__authenticate_vault_client',
                        mock_auth_client)

    def mock_client_init(*args):
        return True

    monkeypatch.setattr(hvac.api.SystemBackend, 'is_initialized',
                        mock_client_init)

    # fails, because cannot reach Vault
    with pytest.raises(requests.exceptions.ConnectionError):
        vault_backend.get_dynamic_secret('salesforce', 'salesforce',
                                         'latest', get_jwt)


def test_get_dynamic_secret_4(monkeypatch, get_jwt):
    # test client initialized
    def mock_auth_client(*args):
        return vault_backend.__get_vault_client('salesforce')

    monkeypatch.setattr(vault_backend, '__authenticate_vault_client',
                        mock_auth_client)

    def mock_client_init(*args):
        return True

    monkeypatch.setattr(hvac.api.SystemBackend, 'is_initialized',
                        mock_client_init)

    # mock client.secrets.transit.read_key()
    def mock_readkey(*args, **kwargs):
        raise hvac.exceptions.Forbidden

    monkeypatch.setattr(hvac.api.secrets_engines.transit.Transit, 'read_key',
                        mock_readkey)

    dek = vault_backend.get_dynamic_secret('salesforce', 'salesforce',
                                           'latest', get_jwt)

    assert dek == b''


def test_get_dynamic_secret_5(monkeypatch, get_jwt):
    # test client initialized
    def mock_auth_client(*args):
        return vault_backend.__get_vault_client('salesforce')

    monkeypatch.setattr(vault_backend, '__authenticate_vault_client',
                        mock_auth_client)

    def mock_client_init(*args):
        return True

    monkeypatch.setattr(hvac.api.SystemBackend, 'is_initialized',
                        mock_client_init)

    # mock client.secrets.transit.read_key()
    def mock_readkey(*args, **kwargs):
        response = {}
        return response

    monkeypatch.setattr(hvac.api.secrets_engines.transit.Transit, 'read_key',
                        mock_readkey)

    dek = vault_backend.get_dynamic_secret('salesforce', 'salesforce',
                                           'latest', get_jwt)

    assert dek == b''


def test_get_dynamic_secret_6(monkeypatch, get_jwt):
    # test client initialized
    def mock_auth_client(*args):
        return vault_backend.__get_vault_client('salesforce')

    monkeypatch.setattr(vault_backend, '__authenticate_vault_client',
                        mock_auth_client)

    def mock_client_init(*args):
        return True

    monkeypatch.setattr(hvac.api.SystemBackend, 'is_initialized',
                        mock_client_init)

    # mock client.secrets.transit.read_key()
    def mock_readkey(*args, **kwargs):
        response = {'data': {'latest_version': 1}}
        return response

    monkeypatch.setattr(hvac.api.secrets_engines.transit.Transit, 'read_key',
                        mock_readkey)

    dek = vault_backend.get_dynamic_secret('salesforce', 'salesforce',
                                           'latest', get_jwt)

    assert dek == b''


def test_get_dynamic_secret_7(monkeypatch, get_jwt):
    # test client initialized
    def mock_auth_client(*args):
        return vault_backend.__get_vault_client('salesforce')

    monkeypatch.setattr(vault_backend, '__authenticate_vault_client',
                        mock_auth_client)

    def mock_client_init(*args):
        return True

    monkeypatch.setattr(hvac.api.SystemBackend, 'is_initialized',
                        mock_client_init)

    # mock client.secrets.transit.read_key()
    def mock_readkey(*args, **kwargs):
        response = {'data': {'latest_version': 1}}
        return response

    monkeypatch.setattr(hvac.api.secrets_engines.transit.Transit, 'read_key',
                        mock_readkey)

    # mock client.secrets.transit.export_key()
    def mock_exportkey(*args, **kwargs):
        return None

    monkeypatch.setattr(hvac.api.secrets_engines.transit.Transit, 'export_key',
                        mock_exportkey)

    dek = vault_backend.get_dynamic_secret('salesforce', 'salesforce',
                                           'latest', get_jwt)

    assert dek == b''


def test_get_dynamic_secret_8(monkeypatch, get_jwt):
    # test client initialized
    def mock_auth_client(*args):
        return vault_backend.__get_vault_client('salesforce')

    monkeypatch.setattr(vault_backend, '__authenticate_vault_client',
                        mock_auth_client)

    def mock_client_init(*args):
        return True

    monkeypatch.setattr(hvac.api.SystemBackend, 'is_initialized',
                        mock_client_init)

    # mock client.secrets.transit.read_key()
    def mock_readkey(*args, **kwargs):
        response = {'data': {'latest_version': 1}}
        return response

    monkeypatch.setattr(hvac.api.secrets_engines.transit.Transit, 'read_key',
                        mock_readkey)

    magic_dek = 'bWFnaWNfZGVr'     # value: magic_dek

    # mock client.secrets.transit.export_key()
    def mock_exportkey(*args, **kwargs):
        response = {'data': {'keys': {'1': magic_dek}}}
        return response

    monkeypatch.setattr(hvac.api.secrets_engines.transit.Transit, 'export_key',
                        mock_exportkey)

    dek = vault_backend.get_dynamic_secret('salesforce', 'salesforce',
                                           1, get_jwt)

    assert dek == b'magic_dek'


def test___get_vault_token(monkeypatch, get_jwt):
    # test with valid token
    client = vault_backend.__get_vault_client('salesforce')

    fake_token = 's.FAKETOKEN'

    def mock_devmode(*args):
        # if get_config_by_keypath() is called with key DEV_MODE,
        # interfere and return true, if called with other keys, ignore
        if args[0] == 'DEV_MODE':
            return True

        if args[0] == [
                'TENANT_CFG.salesforce.backend.VAULT.default_role',
                'VAULT.default_role'
        ]:
            # return default role
            return 'distributey'

    monkeypatch.setattr(config, 'get_config_by_keypath', mock_devmode)

    def mock_vault_auth_jwt(*args, **kwargs):
        # example token: s.f7Ea3C3ojOYE0GRLzmhSGNkE
        response = {'auth': {'client_token': fake_token}}
        return response

    monkeypatch.setattr(
        hvac.api.auth_methods.jwt.JWT, 'jwt_login', mock_vault_auth_jwt)

    token = vault_backend.__get_vault_token(
        client,
        'salesforce',
        get_jwt,
        'jwt',
        'jwt_kid_salesforce_serviceX')

    assert token == fake_token


def test___get_vault_token2(monkeypatch, get_jwt):
    # test with invalid response
    client = vault_backend.__get_vault_client('salesforce')

    fake_token = 's.FAKETOKEN'

    def mock_vault_auth_jwt(*args, **kwargs):
        # example token: s.f7Ea3C3ojOYE0GRLzmhSGNkE
        response = {'auth': {'wrong_key': fake_token}}
        return response

    monkeypatch.setattr(
        hvac.api.auth_methods.jwt.JWT, 'jwt_login', mock_vault_auth_jwt)

    token = vault_backend.__get_vault_token(
        client,
        'salesforce',
        get_jwt,
        'jwt',
        'jwt_kid_salesforce_serviceX')

    assert token == ''


def test___authenticate_vault_client(monkeypatch, get_jwt):
    # test with "valid" token
    client = vault_backend.__get_vault_client('salesforce')

    def mock_client_is_authenticated(*args, **kwargs):
        return True

    monkeypatch.setattr(
        hvac.v1.Client, 'is_authenticated', mock_client_is_authenticated)

    client = vault_backend.__authenticate_vault_client(
        client, 'salesforce', get_jwt)

    assert isinstance(client, hvac.v1.Client)


def test___authenticate_vault_client2(monkeypatch, get_jwt):
    # test with invalid token
    client = vault_backend.__get_vault_client('salesforce')

    def mock_client_is_authenticated(*args, **kwargs):
        return False

    monkeypatch.setattr(
        hvac.v1.Client, 'is_authenticated', mock_client_is_authenticated)

    client = vault_backend.__authenticate_vault_client(
        client, 'salesforce', get_jwt)

    assert client is None
