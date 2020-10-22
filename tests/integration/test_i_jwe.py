import jwe


def test__get_dek_from_vault(get_jwt):
    dek = jwe._get_dek_from_vault(get_jwt, 'salesforce', 'jwe-kid-salesforce-serviceX')
    assert isinstance(dek, bytes)
