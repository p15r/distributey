import jwt
import datetime

expiration_time = 300

private_key = open('mtls/myCert-nopwd.key').read()

payload = {
    'subj': 'salesforce-cacheonlyservice',
    'iss': 'salesforce',
    'aud': 'urn:hyok-wrapper',
    'iat': datetime.datetime.utcnow(),
    'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=expiration_time)
}

token = jwt.encode(payload, private_key, algorithm='RS256').decode('utf-8')

print(f'Bearer {token}\nThis token expires in {expiration_time/60} minutes.')
