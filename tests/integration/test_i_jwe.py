import json
import jwe


def test__get_dek_from_vault(get_jwt):
    dek = jwe._get_dek_from_vault(get_jwt, 'salesforce', 'jwe-kid-salesforce-serviceX')
    assert isinstance(dek, bytes)


def test_get_wrapped_key_as_jwe(get_jwt):
    nonce = 'random-nonce'
    jwe_kid = 'jwe-kid-salesforce-serviceX'
    jwe_token = jwe.get_wrapped_key_as_jwe(get_jwt, 'salesforce', jwe_kid, nonce)
    assert json.loads(jwe_token)['kid'] == jwe_kid
    # test__create_jwe_token_json() tests the rest
