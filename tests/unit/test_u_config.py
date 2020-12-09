import config


class TestUnitConfig():
    def setup_class(self):
        self.tenant = 'salesforce'
        self.jwe_kid = 'jwe-kid-salesforce-serviceX'
        self.jwt_kid = 'jwt_kid_salesforce_serviceX'

    def test_get_config_by_key(self):
        cfg = config.get_config_by_key('LOG_LEVEL')
        assert cfg == 'info'

        try:
            cfg = config.get_config_by_key('NONEXISTING_KEY')
        except KeyError as e:
            assert isinstance(e, KeyError)

    def test_get_key_consumer_cert_by_tenant_and_kid(self):
        cfg = config.get_key_consumer_cert_by_tenant_and_kid(self.tenant, self.jwe_kid)
        assert cfg == 'config/backend/distributey_allservices_key_consumer.crt'

        assert config.get_key_consumer_cert_by_tenant_and_kid('nonexistingtenant', self.jwe_kid) == ''

    def test_get_vault_path_by_tenant_and_kid(self):
        cfg = config.get_vault_path_by_tenant_and_kid(self.tenant, self.jwe_kid)
        assert cfg == 'salesforce:latest'

        assert config.get_vault_path_by_tenant_and_kid('nonexistingtenant', self.jwe_kid) == ''

    def test_get_jwt_algorithm_by_tenant(self):
        cfg = config.get_jwt_algorithm_by_tenant(self.tenant)
        assert cfg == 'RS256'

        assert config.get_jwt_algorithm_by_tenant('nonexistingtenant') == ''

    def test_get_jwt_audience_by_tenant(self):
        cfg = config.get_jwt_audience_by_tenant(self.tenant)
        assert cfg == 'urn:distributey'

        assert config.get_jwt_audience_by_tenant('nonexistingtenant') == ''

    def test_get_jwt_subject_by_tenant(self):
        cfg = config.get_jwt_subject_by_tenant(self.tenant)
        assert cfg == 'cacheonlyservice'

        assert config.get_jwt_subject_by_tenant('nonexistingtenant') == ''

    def test_get_jwt_issuer_by_tenant(self):
        cfg = config.get_jwt_issuer_by_tenant(self.tenant)
        assert cfg == 'salesforce'

        assert config.get_jwt_issuer_by_tenant('nonexistingtenant') == ''

    def test_get_jwt_validation_cert_by_tenant_and_kid(self):
        cfg = config.get_jwt_validation_cert_by_tenant_and_kid(self.tenant, self.jwt_kid)
        assert cfg == 'config/auth/jwt_salesforce_serviceX.pub'

        assert config.get_jwt_validation_cert_by_tenant_and_kid('nonexistingtenant', self.jwt_kid) == ''

    def test_get_vault_default_role_by_tenant(self):
        cfg = config.get_vault_default_role_by_tenant(self.tenant)
        assert cfg == 'salesforce'

        assert config.get_vault_default_role_by_tenant('nonexistingtenant') == ''

    def test_get_vault_auth_jwt_path_by_tenant(self):
        cfg = config.get_vault_auth_jwt_path_by_tenant(self.tenant)
        assert cfg == 'jwt'

        assert config.get_vault_auth_jwt_path_by_tenant('nonexistingtenant') == ''

    def test_get_vault_transit_path_by_tenant(self):
        cfg = config.get_vault_transit_path_by_tenant(self.tenant)
        assert cfg == 'transit'

        assert config.get_vault_transit_path_by_tenant('nonexistingtenant') == ''


