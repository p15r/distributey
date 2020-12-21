#!/usr/bin/env python3

"""
This is a standalone script to monitor distributey with an end to end test.
The end to end test retrieves a transit encryption key from distributey and
compares it against an expected key configured below.

Explain that this script is a key consumer.

Attention: the key used for monitoring must not be used for any other purpose.

SETUP
- Configure all variables below starting w/ CFG_.
  If unsure, leave default value.
- Describe how to generate key consumer key, etc.

Retrieve monitoring secret from Vault:
    curl --header "X-Vault-Token: root" \
    http://vault/v1/transit-monitoring/export/encryption-key/monitoring/1 \
    | jq '.data.keys[]'

Dependencies (requirements.txt):
pycryptodomex==3.9.8
pyjwt[crypto]==1.7.1
requests==2.24.0

Create virtual environment: python3 -m venv /path/to/venv
Activate virtual environment: source /path/to/venv/bin/activate
Install dependencies: python3 -m pip install -r requirements.txt

TODO
- check nonce in answer
"""

import base64
import datetime
import inspect
import logging
import jwt
import json
import requests
import sys

from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA1
from Cryptodome.PublicKey import RSA


# <USER CONFIG>
CFG_DY_ENDPOINT = 'https://localhost:443'
CFG_DY_CA_CERT = 'dev/tmp/nginx.crt'    # "None" if http
CFG_JWE_KID = 'jwe-kid-monitoring'
CFG_EXPECTED_SECRET = 'uo1gpZcIhqUjL/cOWNqVf+xo9FWubaZ3dhRuSZLZSMY='
CFG_KEY_CONSUMER_PRIVKEY = 'dev/tmp/key_consumer_key.key'
CFG_JWT_SIGNING_PRIVKEY = 'dev/tmp/jwt.key'
CFG_JWT_EXPIRATION_TIME = 300     # ms
CFG_JWT_KID = 'jwt_kid_monitoring'
# </USER CONFIG>

jwe_nonce = 'a-randrom-nonce'
dy_api_path = f'/v1/monitoring/{CFG_JWE_KID}?requestID={jwe_nonce}'

logFormatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
consoleHandler = logging.StreamHandler()    # log to stderr
consoleHandler.setFormatter(logFormatter)

logger = logging.getLogger()
logger.addHandler(consoleHandler)
logger.setLevel(logging.DEBUG)


def trace_enter(current_frame):
    func_name = current_frame.f_code.co_name
    func_args = current_frame.f_code.co_varnames
    file_name = current_frame.f_code.co_filename
    line_no = current_frame.f_code.co_firstlineno

    logger.debug(
        f'({file_name}:{line_no}) Entering "{func_name}" args: {func_args}')


def trace_exit(current_frame, ret):
    func_name = current_frame.f_code.co_name
    file_name = current_frame.f_code.co_filename
    line_no = current_frame.f_code.co_firstlineno

    logger.debug(f'({file_name}:{line_no}) Exiting "{func_name}" ret: {ret}')


def create_auth_header() -> str:
    trace_enter(inspect.currentframe())

    with open(CFG_JWT_SIGNING_PRIVKEY, 'rb') as f:
        private_key = f.read()

    exp = datetime.datetime.utcnow() + \
        datetime.timedelta(seconds=CFG_JWT_EXPIRATION_TIME)

    payload = {
        'sub': 'monitoring',
        'iss': 'monitoring',
        'aud': 'urn:distributey',
        'iat': datetime.datetime.utcnow(),
        'exp': exp
    }

    token = jwt.encode(
        payload, private_key, algorithm='RS256',
        headers={'kid': CFG_JWT_KID}).decode('utf-8')

    ret = f'Bearer {token}'

    trace_exit(inspect.currentframe(), ret)

    return ret


def request_jwe() -> str:
    trace_enter(inspect.currentframe())

    auth_header = create_auth_header()

    r = requests.get(
        f'{CFG_DY_ENDPOINT}{dy_api_path}',
        headers={'Authorization': auth_header},
        verify=CFG_DY_CA_CERT)

    ret = r.json()

    trace_exit(inspect.currentframe(), ret)
    return ret


def decrypt_cek(cek_cipher):
    trace_enter(inspect.currentframe())

    with open(CFG_KEY_CONSUMER_PRIVKEY, 'rb') as f:
        rsa_privkey = f.read()

    private_key = RSA.import_key(rsa_privkey)

    # bcs protected header is RSA-OAEP
    cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA1)
    ret = cipher_rsa.decrypt(cek_cipher)

    trace_exit(inspect.currentframe(), ret)
    return ret


def decrypt_dek(cek, protected_header, dek_cipher, iv, auth_tag):
    trace_enter(inspect.currentframe())

    aes_cipher = AES.new(cek, AES.MODE_GCM, nonce=iv, mac_len=16)

    str_protected_header = json.dumps(protected_header)
    b64_protected_header = base64.b64encode(str_protected_header.encode())
    ascii_b64_protected_header = \
        b64_protected_header.decode().encode('ascii', errors='strict')
    print(ascii_b64_protected_header)
    aes_cipher.update(ascii_b64_protected_header)
    dek = aes_cipher.decrypt_and_verify(dek_cipher, auth_tag)

    bytes_dek = base64.b64encode(dek)
    ret = bytes_dek.decode()

    trace_exit(inspect.currentframe(), ret)
    return ret


def verify_protected_header(protected_header):
    trace_enter(inspect.currentframe())

    jwe_alg = protected_header['alg']   # RSA-OAEP
    jwe_enc = protected_header['enc']   # A256GCM
    # check other header attribs as well

    ret = True

    trace_exit(inspect.currentframe(), ret)
    return ret


def decode_jwe(jwe_token: str) -> str:
    trace_enter(inspect.currentframe())

    jwe_kid = jwe_token.get('kid', '')
    jwe = jwe_token.get('jwe', '')

    b64_protected_header = jwe.split('.')[0]
    b64_cek_cipher = jwe.split('.')[1]
    b64_iv = jwe.split('.')[2]
    b64_dek_cipher = jwe.split('.')[3]
    b64_auth_tag = jwe.split('.')[4]

    str_protected_header = base64.urlsafe_b64decode(b64_protected_header)
    protected_header = json.loads(str_protected_header)
    cek_cipher = base64.urlsafe_b64decode(b64_cek_cipher)
    iv = base64.urlsafe_b64decode(b64_iv)
    dek_cipher = base64.urlsafe_b64decode(b64_dek_cipher)
    auth_tag = base64.urlsafe_b64decode(b64_auth_tag)

    jwe_kid = protected_header.get('kid', '')
    if jwe_kid == 'jwe-kid-monitoring':
        print(f'jwe kid matches: {jwe_kid}')
    else:
        print(f'jwe kid does not match: {jwe_kid}')
        return ''

    if not verify_protected_header(protected_header):
        return ''

    cek = decrypt_cek(cek_cipher)

    ret = decrypt_dek(cek, protected_header, dek_cipher, iv, auth_tag)

    trace_exit(inspect.currentframe(), ret)
    return ret


def compare(dek: str):
    trace_enter(inspect.currentframe())

    ret = None

    if dek == CFG_EXPECTED_SECRET:
        logger.info('OK. Retrieved secret matches.')
        ret = True
    else:
        logger.info('FATAL. Retrieved secret does not match.')
        ret = False

    trace_exit(inspect.currentframe(), ret)
    return ret


if __name__ == '__main__':
    jwe = request_jwe()
    dek = decode_jwe(jwe)
    ret = compare(dek)

    if ret:
        sys.exit(0)
    else:
        sys.exit(1)
