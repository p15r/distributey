"""
Creates a JWT token.
"""

import sys
import datetime
import jwt

with open('dev/tmp/jwt.key') as f:
    private_key = f.read()

monitoring_tenant = False

if len(sys.argv) > 1:
    if sys.argv[1] == '-m':
        monitoring_tenant = True

if monitoring_tenant:
    sub = 'monitoring'
    iss = 'monitoring'
    header = dict(kid='jwt_kid_monitoring')
else:
    sub = 'cacheonlyservice'
    iss = 'salesforce'
    header = dict(kid='jwt_kid_salesforce_serviceX')

expiration_time = 300
payload = {
    'sub': sub,
    'iss': iss,
    'aud': 'urn:distributey',
    'iat': datetime.datetime.utcnow(),
    'exp': datetime.datetime.utcnow() + datetime.timedelta(
        seconds=expiration_time)
}

token = jwt.encode(
    payload, private_key, algorithm='RS256', headers=header).decode('utf-8')

print(f'Bearer {token}')
