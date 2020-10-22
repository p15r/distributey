import vault_backend


class TestVaultBackend():
    def test_get_dynamic_secret(self, get_jwt):
        key = vault_backend.get_dynamic_secret('salesforce', 'latest', get_jwt)
        assert isinstance(key, bytes)

        if len(key) > 0:
            assert True, 'Successfully retrieved dek from Vault.'
        else:
            assert False, 'Retrieved dek with zero length.'
