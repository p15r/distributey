import json
import jwe


def test_get_wrapped_key_as_jwe(get_jwt):
    nonce = 'random-nonce'
    jwe_kid = 'jwe-kid-salesforce-serviceX'
    jwe_token = jwe.get_wrapped_key_as_jwe(b'randomdek', 'salesforce', jwe_kid, nonce)
    assert json.loads(jwe_token)['kid'] == jwe_kid
    # test__create_jwe_token_json() covers all other code
