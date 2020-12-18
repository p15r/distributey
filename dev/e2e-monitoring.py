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

from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA1
from Cryptodome.PublicKey import RSA


# <USER CONFIG>
CFG_DY_ENDPOINT = 'https://localhost:443'
CFG_DY_CA_CERT = 'dev/tmp/nginx.crt'    # "None" if http
CFG_JWE_KID = 'jwe-kid-monitoring'
CFG_EXPECTED_SECRET = 'v41tvGuri+VnQwXDWlsELj4AkL5TWV1WZDgvuoHt6gM='
CFG_KEY_CONSUMER_PRIVKEY = 'dev/tmp/key_consumer_key.key'
CFG_JWT_SIGNING_PRIVKEY = 'dev/tmp/jwt.key'
CFG_JWT_EXPIRATION_TIME = 300     # ms
CFG_JWT_KID = 'jwt_kid_monitoring'
# </USER CONFIG>

jwe_nonce = 'a-randrom-nonce'
dy_api_path = f'/v1/monitoring/{CFG_JWE_KID}?requestID={jwe_nonce}'

logFormatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
consoleHandler = logging.StreamHandler()    # log to stderr
consoleHandler.setFormatter(logFormatter)

logger = logging.getLogger()
logger.addHandler(consoleHandler)
logger.setLevel(logging.DEBUG)


def create_auth_header() -> str:
    logger.debug(f'Entering method "{inspect.currentframe().f_code.co_name}".')

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

    auth_header = f'Bearer {token}'

    logger.debug(
        f'Exiting method "{inspect.currentframe().f_code.co_name}".'
        f' Return value: "{auth_header}" ({type(auth_header)})')
    return auth_header


def request_jwe() -> str:
    logger.debug(f'Entering method "{inspect.currentframe().f_code.co_name}".')

    auth_header = create_auth_header()

    r = requests.get(
        f'{CFG_DY_ENDPOINT}{dy_api_path}',
        headers={'Authorization': auth_header},
        verify=CFG_DY_CA_CERT)

    r = r.json()

    logger.debug(
        f'Exiting method "{inspect.currentframe().f_code.co_name}".'
        f' Return value: "{r}" ({type(r)})')
    return r


def decrypt_cek(cek_cipher):
    logger.debug(f'Entering method "{inspect.currentframe().f_code.co_name}".'
                 f' Param: cek_cipher="{cek_cipher}" ({type(cek_cipher)}).')

    with open(CFG_KEY_CONSUMER_PRIVKEY, 'rb') as f:
        rsa_privkey = f.read()

    private_key = RSA.import_key(rsa_privkey)

    # bcs protected header is RSA-OAEP
    cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA1)
    cek = cipher_rsa.decrypt(cek_cipher)


    logger.debug(
        f'Exiting method "{inspect.currentframe().f_code.co_name}".'
        f' Return value: "{cek}" ({type(cek)})')
    return cek


def decrypt_dek(cek, protected_header, dek_cipher, iv, auth_tag):
    logger.debug(f'Entering method "{inspect.currentframe().f_code.co_name}".'
                 f' Param: cek="{cek}" ({type(cek)}).'
                 f' Param: protected_header="{protected_header}"'
                 f' ({type(protected_header)}).'
                 f' Param: dek_cipher="{dek_cipher}" ({type(dek_cipher)}).'
                 f' Param: iv="{iv}" ({type(iv)}).'
                 f' Param: auth_tag="{auth_tag}" ({type(auth_tag)}).')

    aes_cipher = AES.new(cek, AES.MODE_GCM, nonce=iv, mac_len=16)

    str_protected_header = json.dumps(protected_header)
    b64_protected_header = base64.b64encode(str_protected_header.encode())
    ascii_b64_protected_header = \
        b64_protected_header.decode().encode('ascii', errors='strict')
    print(ascii_b64_protected_header)
    aes_cipher.update(ascii_b64_protected_header)
    dek = aes_cipher.decrypt_and_verify(dek_cipher, auth_tag)

    bytes_dek = base64.b64encode(dek)
    dek = bytes_dek.decode()

    logger.debug(
        f'Exiting method "{inspect.currentframe().f_code.co_name}".'
        f' Return value: "{dek}" ({type(dek)})')
    return dek


def verify_protected_header(protected_header):
    logger.debug(f'Entering method "{inspect.currentframe().f_code.co_name}".'
                 f' Param: protected_header="{protected_header}"'
                 f' ({type(protected_header)}).')

    jwe_alg = protected_header['alg']   # RSA-OAEP
    jwe_enc = protected_header['enc']   # A256GCM
    # check other header attribs as well

    return True


def decode_jwe(jwe_token: str) -> str:
    logger.debug(f'Entering method "{inspect.currentframe().f_code.co_name}".'
                 f' Param: jwe_token="{jwe_token}" ({type(jwe_token)}).')

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

    dek = decrypt_dek(cek, protected_header, dek_cipher, iv, auth_tag)

    logger.debug(
        f'Exiting method "{inspect.currentframe().f_code.co_name}".'
        f' Return value: "{dek}" ({type(dek)})')
    return dek


def compare(dek: str):
    logger.debug(f'Entering method "{inspect.currentframe().f_code.co_name}".'
                 f' Param: dek="{dek}" ({type(dek)}).')

    ret = None

    if dek == CFG_EXPECTED_SECRET:
        logger.info('OK. Retrieved secret matches.')
        ret = True
    else:
        logger.info('FATAL. Retrieved secret does not match.')
        ret = False

    logger.debug(
        f'Exiting method "{inspect.currentframe().f_code.co_name}".'
        f' Return value: "{ret}" ({type(ret)})')

    return ret


if __name__ == '__main__':
    jwe = request_jwe()
    dek = decode_jwe(jwe)
    compare(dek)

    # sys.exit(1) if compare fails
