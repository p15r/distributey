import jwt
import datetime

expiration_time = 300

with open('dev/tmp/jwt.key') as f:
    private_key = f.read()

payload = {
    'sub': 'cacheonlyservice',
    'iss': 'salesforce',
    'aud': 'urn:hyok-wrapper',
    'iat': datetime.datetime.utcnow(),
    'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=expiration_time)
}

token = jwt.encode(
        payload, private_key, algorithm='RS256', headers=dict(kid='jwt_kid_salesforce_serviceX')).decode('utf-8')

print(f'Bearer {token}')
