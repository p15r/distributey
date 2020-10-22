import pytest
import config
import jwe


@pytest.fixture(autouse=True)
def setup_module(monkeypatch):
    monkeypatch.setattr(config, 'CFG_PATH', 'config/config.json')


def test__get_dek_from_vault(get_jwt):
    dek = jwe._get_dek_from_vault(get_jwt, 'salesforce', 'jwe-kid-salesforce-serviceX')
    assert isinstance(dek, bytes)
