"""
Creates a JWT token.
"""

import sys
import datetime
import jwt

monitoring_tenant = False
salesforce_dev_tenant = False

if len(sys.argv) > 1:
    if sys.argv[1] == '-m':
        monitoring_tenant = True
    if sys.argv[1] == '-d':
        salesforce_dev_tenant = True

if monitoring_tenant:
    sub = 'monitoring'
    iss = 'monitoring'
    header = dict(kid='jwt_kid_monitoring')
    jwt_key_path = 'dev/tmp/jwt.key'
elif salesforce_dev_tenant:
    sub = 'cacheonlyservice-dev'
    iss = 'salesforce-dev'
    header = dict(kid='jwt_kid_salesforce_dev')
    jwt_key_path = 'dev/tmp/jwt-dev.key'
else:
    sub = 'cacheonlyservice'
    iss = 'salesforce'
    header = dict(kid='jwt_kid_salesforce_serviceX')
    jwt_key_path = 'dev/tmp/jwt.key'

private_key = ''
with open(jwt_key_path) as f:
    private_key = f.read()

expiration_time = 300
payload = {
    'sub': sub,
    'iss': iss,
    'aud': 'urn:distributey',
    'iat': datetime.datetime.utcnow(),
    'exp': datetime.datetime.utcnow() + datetime.timedelta(
        seconds=expiration_time)
}

token = jwt.encode(payload, private_key, algorithm='RS256', headers=header)

print(f'Bearer {token}')
