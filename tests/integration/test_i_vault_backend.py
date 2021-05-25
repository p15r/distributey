import hvac
import vault_backend


class TestVaultBackend():
    def test_get_dynamic_secret(self, get_jwt):
        key = vault_backend.get_dynamic_secret('salesforce', 'salesforce',
                                               'latest', get_jwt)
        assert isinstance(key, bytearray)

        if len(key) > 0:
            assert True, 'Successfully retrieved dek from Vault.'
        else:
            assert False, 'Retrieved dek with zero length.'

# test get_vault_token, get_vault_client


def test___get_vault_token(monkeypatch, get_jwt):
    client = vault_backend.__get_vault_client()

    token = vault_backend.__get_vault_token(
        client,
        'salesforce',
        get_jwt,
        'jwt',
        'jwt_kid_salesforce_serviceX')

    # example token: s.Yc3hPcXPJgDYFheaYEG3wgKe'
    assert token
    assert token.startswith('s.')
    assert len(token) == 26


def test___authenticate_vault_client(monkeypatch, get_jwt):
    # test with "valid" token
    client = vault_backend.__get_vault_client()

    client = vault_backend.__authenticate_vault_client(
        client, 'salesforce', get_jwt)

    assert isinstance(client, hvac.v1.Client)
    assert client.is_authenticated()
