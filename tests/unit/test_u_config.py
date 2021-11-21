"""Tests config module."""

import config


class TestUnitConfig():
    def setup_class(self):
        self.tenant = 'salesforce'
        self.jwe_kid = 'jwe-kid-salesforce-serviceX'
        self.jwt_kid = 'jwt_kid_salesforce_serviceX'

    def test__is_cfg_path_valid(self):
        # test w/ invalid path type
        assert config._is_cfg_path_valid(1) is False

        # test w/ too long path
        long_path = ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1')
        assert config._is_cfg_path_valid(long_path) is False

        # test w/ missing 'config.json' at the end
        assert config._is_cfg_path_valid('/path/') is False

    def test_get_config_by_keypath(self):
        cfg = config.get_config_by_keypath('LOG_LEVEL')
        assert cfg == 'info'

        try:
            cfg = config.get_config_by_keypath('NONEXISTING_KEY')
        except KeyError as e:
            assert isinstance(e, KeyError)

    def test_get_key_consumer_cert_by_tenant_and_kid(self):
        cfg = config.get_key_consumer_cert_by_tenant_and_kid(self.tenant,
                                                             self.jwe_kid)
        assert cfg == 'config/backend/distributey_serviceX_key_consumer.crt'

        assert config.get_key_consumer_cert_by_tenant_and_kid(
            'nonexistingtenant', self.jwe_kid) is False

    def test_get_vault_path_by_tenant_and_kid(self):
        cfg = config.get_vault_path_by_tenant_and_kid(self.tenant,
                                                      self.jwe_kid)
        assert cfg == 'salesforce:latest'

        assert config.get_vault_path_by_tenant_and_kid(
            'nonexistingtenant', self.jwe_kid) is False

    def test_get_jwt_algorithm_by_tenant(self):
        cfg = config.get_jwt_algorithm_by_tenant(self.tenant)
        assert cfg == 'RS256'

        assert config.get_jwt_algorithm_by_tenant('nonexistingtenant') is False

    def test_get_jwt_audience_by_tenant(self):
        cfg = config.get_jwt_audience_by_tenant(self.tenant)
        assert cfg == 'urn:distributey'

        assert config.get_jwt_audience_by_tenant('nonexistingtenant') is False

    def test_get_jwt_subject_by_tenant(self):
        cfg = config.get_jwt_subject_by_tenant(self.tenant)
        assert cfg == 'cacheonlyservice'

        assert config.get_jwt_subject_by_tenant('nonexistingtenant') is False

    def test_get_jwt_issuer_by_tenant(self):
        cfg = config.get_jwt_issuer_by_tenant(self.tenant)
        assert cfg == 'salesforce'

        assert config.get_jwt_issuer_by_tenant('nonexistingtenant') is False

    def test_get_jwt_validation_cert_by_tenant_and_kid(self):
        cfg = config.get_jwt_validation_cert_by_tenant_and_kid(self.tenant,
                                                               self.jwt_kid)
        assert cfg == 'config/auth/jwt_salesforce_serviceX.pub'

        assert config.get_jwt_validation_cert_by_tenant_and_kid(
            'nonexistingtenant', self.jwt_kid) is False

    def test_get_vault_default_role_by_tenant(self):
        cfg = config.get_vault_default_role_by_tenant(self.tenant)
        assert cfg == 'salesforce'

        assert config.get_vault_default_role_by_tenant('nonexistingtenant') \
            is False

    def test_get_vault_auth_jwt_path_by_tenant(self):
        cfg = config.get_vault_auth_jwt_path_by_tenant(self.tenant)
        assert cfg == 'jwt'

        assert config.get_vault_auth_jwt_path_by_tenant('nonexistingtenant') \
            is False

    def test_get_vault_transit_path_by_tenant(self):
        cfg = config.get_vault_transit_path_by_tenant(self.tenant)
        assert cfg == 'transit'

        assert config.get_vault_transit_path_by_tenant('nonexistingtenant') \
            is False
