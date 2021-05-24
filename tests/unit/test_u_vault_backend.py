"""Testing for vault_backend module."""

import hvac
import pytest
import requests
import config
import vault_backend


def test___get_vault_client(monkeypatch):
    # valid test
    client = vault_backend.__get_vault_client()
    assert isinstance(client, hvac.Client)

    # test w/ no VAULT_CERT
    def mock_vault_cert(*args):
        if args[0] == 'VAULT_CACERT':
            return False

    monkeypatch.setattr(config, 'get_config_by_keypath', mock_vault_cert)
    client = vault_backend.__get_vault_client()
    assert isinstance(client, hvac.Client)


def test___authenticate_vault_client(get_jwt):
    client = vault_backend.__get_vault_client()

    # test w/o connection to vault
    auth_client = vault_backend.__authenticate_vault_client(client,
                                                            'salesforce',
                                                            get_jwt)

    assert auth_client is None


def test_get_dynamic_secret(monkeypatch, get_jwt):
    # test w/o connection to vault
    dek = vault_backend.get_dynamic_secret('salesforce', 'salesforce',
                                           'latest', get_jwt)

    assert dek == b''

    # test w/ failing client creation
    def mock_client():
        return None

    monkeypatch.setattr(vault_backend, '__get_vault_client', mock_client)

    dek = vault_backend.get_dynamic_secret('salesforce', 'salesforce',
                                           'latest', get_jwt)


def test_get_dynamic_secret_2(monkeypatch, get_jwt):
    # test client not initialized
    def mock_auth_client(*args):
        return vault_backend.__get_vault_client()

    monkeypatch.setattr(vault_backend, '__authenticate_vault_client',
                        mock_auth_client)

    def mock_client_init(*args):
        return False

    monkeypatch.setattr(hvac.api.SystemBackend, 'is_initialized',
                        mock_client_init)

    dek = vault_backend.get_dynamic_secret('salesforce', 'salesforce',
                                           'latest', get_jwt)

    assert dek == b''


def test_get_dynamic_secret_3(monkeypatch, get_jwt):
    # test client initialized
    def mock_auth_client(*args):
        return vault_backend.__get_vault_client()

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
        return vault_backend.__get_vault_client()

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
        return vault_backend.__get_vault_client()

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
        return vault_backend.__get_vault_client()

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
        return vault_backend.__get_vault_client()

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
        return vault_backend.__get_vault_client()

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
