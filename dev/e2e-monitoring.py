#!/usr/bin/env python3

"""
This is a standalone script to monitor distributey with an end-to-end test.
This test retrieves a transit encryption key from distributey and
verifies it against an expected key configured below.

From distributey's perspective, this script is a key consumer and must be
configured accordingly. You can find an example config for a "monitoring"
tenant in dev/example-config.json.

Note: the transit encryption key for monitoring must not be used for any
other purposes.

-----
SETUP
-----

0. Install dependencies of this script:
   - Create requirements.txt with the following content:
     pycryptodomex==3.9.8
     pyjwt[crypto]==1.7.1
     requests==2.24.0

   - Create virtual environment:
     python3 -m venv venv

   - Activate virtual environment:
     source venv/bin/activate

   - Install dependencies:
     python3 -m pip install -r requirements.txt

1. Retrieve monitoring tenant transit encryption key in Vault:
   curl --header "X-Vault-Token: root" \
   http://vault/v1/transit-monitoring/export/encryption-key/monitoring/1 \
   | jq '.data.keys[]'

2. Configure all variables below starting with "CFG_".
   If unsure, keep the default value.

   - CFG_DY_ENDPOINT: URL of distributey.
   - CFG_DY_CA_CERT: HTTPS public cert of distributey.
   - CFG_EXPECTED_SECRET: monitoring transit encryption key stored in Vault.
   - CFG_KEY_CONSUMER_PRIVKEY: Key used to decrypt CEK. See dev/dev_setup.sh.
   - CFG_JWT_SIGNING_PRIVKEY: Key used to sign JWT. See dev/dev_setup.sh.

3. Run end-to-end test:
   python3 dev/e2e-monitoring.py

   If the test is successful, you should see an output similar to:

   "2020-12-30 09:32:37,739 [INFO] OK. Retrieved secret matches."
"""

import base64
import datetime
import inspect
import logging
import json
import jwt
import requests
import sys
import types
from typing import Any, Optional

from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA1
from Cryptodome.PublicKey import RSA

# <USER CONFIG>
CFG_DY_ENDPOINT = 'https://localhost:443'
CFG_DY_CA_CERT = 'dev/tmp/nginx.crt'    # "None" if http
CFG_JWE_KID = 'jwe-kid-monitoring'
CFG_JWE_ALG = 'RSA-OAEP'
CFG_JWE_ENC = 'A256GCM'
CFG_EXPECTED_SECRET = 'monitoring-transit-encryption-key-from-vault'
CFG_KEY_CONSUMER_PRIVKEY = 'dev/tmp/key_consumer_key.key'
CFG_JWT_SIGNING_PRIVKEY = 'dev/tmp/jwt.key'
CFG_JWT_EXPIRATION_TIME = 300     # ms
CFG_JWT_KID = 'jwt_kid_monitoring'
# </USER CONFIG>

jwe_nonce = 'a-very-randrom-nonce'
dy_api_path = f'/v1/monitoring/{CFG_JWE_KID}'

logFormatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
consoleHandler = logging.StreamHandler()    # log to stderr
consoleHandler.setFormatter(logFormatter)

logger = logging.getLogger()
logger.addHandler(consoleHandler)
logger.setLevel(logging.INFO)


def __trace(current_frame: Optional[types.FrameType]) -> tuple:
    if isinstance(current_frame, types.FrameType):
        func_name = current_frame.f_code.co_name
        # getargvalues is deprecated, use inspect.signature() instead
        func_args = inspect.getargvalues(current_frame)
        file_name = current_frame.f_code.co_filename
        line_no = current_frame.f_code.co_firstlineno
    else:
        # inspect.currentframe() might return None,
        # in case of "exotic" python runtime
        logger.error(f'Failed to inspect frame: "{current_frame}".')
        return ('error', 'error', 'error', 'error')

    return func_name, func_args, file_name, line_no


def trace_enter(current_frame: Optional[types.FrameType]) -> None:
    func_name, func_args, file_name, line_no = __trace(current_frame)

    logger.debug(
        f'({file_name}:{line_no}) Entering "{func_name}" args: {func_args}')


def trace_exit(current_frame: Optional[types.FrameType], ret: Any) -> None:
    func_name, func_args, file_name, line_no = __trace(current_frame)

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


def request_jwe() -> dict:
    trace_enter(inspect.currentframe())

    auth_header = create_auth_header()

    r = requests.get(
        f'{CFG_DY_ENDPOINT}{dy_api_path}',
        headers={'Authorization': auth_header},
        verify=CFG_DY_CA_CERT,
        params={'requestId': jwe_nonce})

    ret = r.json()

    trace_exit(inspect.currentframe(), ret)
    return ret


def decrypt_cek(cek_cipher: bytes) -> bytes:
    trace_enter(inspect.currentframe())

    with open(CFG_KEY_CONSUMER_PRIVKEY, 'rb') as f:
        rsa_privkey = f.read()

    private_key = RSA.import_key(rsa_privkey)

    # bcs protected header defines RSA-OAEP
    cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA1)
    ret = cipher_rsa.decrypt(cek_cipher)

    trace_exit(inspect.currentframe(), ret)
    return ret


def decrypt_dek(
        cek: bytes, protected_header: dict, dek_cipher: bytes, iv: bytes,
        auth_tag: bytes) -> str:
    trace_enter(inspect.currentframe())

    aes_cipher = AES.new(cek, AES.MODE_GCM, nonce=iv, mac_len=16)

    str_protected_header = json.dumps(protected_header)
    b64_protected_header = base64.b64encode(str_protected_header.encode())
    ascii_b64_protected_header = \
        b64_protected_header.decode().encode('ascii', errors='strict')

    aes_cipher.update(ascii_b64_protected_header)
    dek = aes_cipher.decrypt_and_verify(dek_cipher, auth_tag)

    b64_dek = base64.b64encode(dek)
    ret = b64_dek.decode()

    trace_exit(inspect.currentframe(), ret)
    return ret


def verify_protected_header(protected_header: dict) -> bool:
    trace_enter(inspect.currentframe())

    protected_header_map = {
        'alg': CFG_JWE_ALG,
        'enc': CFG_JWE_ENC,
        'kid': CFG_JWE_KID,
        'jti': jwe_nonce
    }

    for key, value in protected_header_map.items():
        received_field = protected_header.get(key, '')
        if received_field != value:
            logger.error(
                f'Incorrect protected header field "{key}",'
                f' Got "{received_field}", expected "{value}".')
            trace_exit(inspect.currentframe(), False)
            return False

    trace_exit(inspect.currentframe(), True)
    return True


def unserialize_jwe(jwe: str) -> tuple:
    trace_enter(inspect.currentframe())

    split_jwe = jwe.split('.')

    if not len(split_jwe) == 5:
        logger.error(f'Failed to split jwe into 5 segments: {split_jwe}')
        trace_exit(inspect.currentframe(), '')
        return ()

    b64_protected_header = split_jwe[0]
    b64_cek_cipher = split_jwe[1]
    b64_iv = split_jwe[2]
    b64_dek_cipher = split_jwe[3]
    b64_auth_tag = split_jwe[4]

    str_protected_header = base64.urlsafe_b64decode(b64_protected_header)
    protected_header = json.loads(str_protected_header)

    cek_cipher = base64.urlsafe_b64decode(b64_cek_cipher)
    iv = base64.urlsafe_b64decode(b64_iv)
    dek_cipher = base64.urlsafe_b64decode(b64_dek_cipher)
    auth_tag = base64.urlsafe_b64decode(b64_auth_tag)

    ret = (protected_header, cek_cipher, iv, dek_cipher, auth_tag)

    trace_exit(inspect.currentframe(), ret)
    return ret


def decode_jwe(jwe_token: dict) -> str:
    trace_enter(inspect.currentframe())

    jwe_kid = jwe_token.get('kid', '')
    jwe = jwe_token.get('jwe', '')

    jwe_tuple = \
        unserialize_jwe(jwe)

    if not jwe_tuple:
        logger.error(f'Failed to unserialize jwe. Got "{jwe_tuple}".')
        trace_exit(inspect.currentframe(), '')
        return ''

    protected_header, cek_cipher, iv, dek_cipher, auth_tag = jwe_tuple

    jwe_kid = protected_header.get('kid', '')
    if jwe_kid != CFG_JWE_KID:
        logger.error(
            f'Retrieved jwe kid "{jwe_kid}" does not match'
            f' with configured kid "{CFG_JWE_KID}".')

        trace_exit(inspect.currentframe(), '')
        return ''

    if not verify_protected_header(protected_header):
        logger.error(
            f'Failed to verify protected header "{protected_header}".')
        trace_exit(inspect.currentframe(), '')
        return ''

    cek = decrypt_cek(cek_cipher)

    if not cek:
        logger.error('Failed to decrypt dek.')
        trace_exit(inspect.currentframe(), '')
        return ''

    ret = decrypt_dek(cek, protected_header, dek_cipher, iv, auth_tag)

    if not ret:
        logger.error('Failed to decrypt dek.')
        trace_exit(inspect.currentframe(), ret)
        return ''

    trace_exit(inspect.currentframe(), ret)
    return ret


def verify_retrieved_dek(dek: str) -> bool:
    trace_enter(inspect.currentframe())

    ret = None

    if dek == CFG_EXPECTED_SECRET:
        logger.info('OK. Retrieved secret matches.')
        ret = True
    else:
        logger.error('FATAL. Retrieved secret does not match.')
        ret = False

    trace_exit(inspect.currentframe(), ret)
    return ret


if __name__ == '__main__':
    jwe = request_jwe()

    if not jwe:
        logger.error('Failed to request jwe.')
        sys.exit(1)

    dek = decode_jwe(jwe)

    if not dek:
        logger.error('Failed to decode jwe.')
        sys.exit(1)

    compare = verify_retrieved_dek(dek)

    if not compare:
        sys.exit(1)

    sys.exit(0)
