import jwt

private_key = open('mtls/myCert-nopwd.key').read()

payload = {
    'sub': 'salesforce-cacheonlyservice',
    'aud': 'urn:hyok-wrapper'
}

token = jwt.encode(payload, private_key, algorithm='RS256').decode('utf-8')

print(f'Token: Bearer {token}')
