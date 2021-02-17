"""Testing for vault_backend module."""

import hvac
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


def test___get_vault_client_2(monkeypatch):
    # test w/ forced exception
    def mock_raise(*args):
        if args[0] == 'VAULT_CACERT':
            raise Exception('testing')
        elif args[0] == 'VAULT_MTLS_CLIENT_CERT':
            return 'config/mtls_auth.crt'
        else:
            return 'config/mtls_auth.key'

    monkeypatch.setattr(config, 'get_config_by_keypath', mock_raise)

    client = vault_backend.__get_vault_client()

    assert client is None


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
