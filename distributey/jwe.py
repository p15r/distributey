"""
Creates JWEs to securely distribute key material.

It follows https://help.salesforce.com/
    articleView?id=security_pe_byok_cache_create.htm&type=5
to support compliance with Salesforce's cache-only key service.

Note that pyCryptoDome uses the terms IV and NONCE interchangeably:
- https://pycryptodome.readthedocs.io/en/latest/src/cipher/
    modern.html#modern-modes-of-operation-for-symmetric-block-ciphers
"""

import base64
import json
import inspect
from typing import Tuple
from Cryptodome.Hash import SHA1
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from dy_logging import logger
from dy_trace import trace_enter, trace_exit
import config


def _get_key_consumer_cert(tenant: str, jwe_kid: str) -> str:
    trace_enter(inspect.currentframe())
    # key consumer cert: certificate from key consumer to wrap cek.

    if not (key_consumer_cert_path :=
            config.get_key_consumer_cert_by_tenant_and_kid(tenant, jwe_kid)):
        logger.error('Cannot find key consumer certificate for '
                     '"%s/%s". '
                     'Configure it in config/config.json.', tenant, jwe_kid)
        trace_exit(inspect.currentframe(), '')
        return ''

    try:
        cert = open(key_consumer_cert_path).read().strip()
    except Exception as exc:
        logger.error('Cannot read key consumer certificate at '
                     '"%s": %s.', key_consumer_cert_path, exc)
        trace_exit(inspect.currentframe(), '')
        return ''

    trace_exit(inspect.currentframe(), cert)
    return cert


def _encrypt_cek_with_key_consumer_key(tenant: str, jwe_kid: str,
                                       priv_cek: bytes) -> bytes:
    trace_enter(inspect.currentframe())

    # Encrypt cek with public key from key consumer using RSAES-OAEP
    # (BASE64URL(JWE Encrypted CEK Key))
    if not (key_consumer_cert := _get_key_consumer_cert(tenant, jwe_kid)):
        logger.error('Cannot get key consumer certificate for tenant '
                     '"%s" with JWE kid "%s".', tenant, jwe_kid)
        trace_exit(inspect.currentframe(), b'')
        return b''

    rsa_cert = RSA.importKey(key_consumer_cert)
    cek_cipher = PKCS1_OAEP.new(rsa_cert, hashAlgo=SHA1)
    cek_ciphertext = cek_cipher.encrypt(priv_cek)
    b64_cek_ciphertext = base64.urlsafe_b64encode(cek_ciphertext)

    trace_exit(inspect.currentframe(), b64_cek_ciphertext)
    return b64_cek_ciphertext


def _encrypt_dek_with_cek(
    priv_cek: bytes,
    initialization_vector: bytes,
    dek: bytes,
        ascii_b64_protected_header: bytes) -> Tuple[bytes, bytes]:
    """
    Wrap dek with cek:
    - Perform authenticated encryption on dek with the AES GCM algorithm.
    - Use cek as encryption key, the initialization vector,
      and the protecred header as Additional Authenticated Data value.
    - Request a 128-bit Authentication Tag output.
    """
    trace_enter(inspect.currentframe())

    # mac_len=16 bytes: 128 bit authentication tag
    dek_cipher = AES.new(priv_cek, AES.MODE_GCM, nonce=initialization_vector,
                         mac_len=16)

    # add additional authenticated data (aad)
    dek_cipher.update(ascii_b64_protected_header)

    # TODO: Autom. padding helpful? Might replace pycryptodome anyway.
    # from Cryptodome.Util.Padding import pad
    # encrypted_dek, tag = \
    #   dek_cipher.encrypt_and_digest(pad(dek, AES.block_size))
    encrypted_dek, tag = dek_cipher.encrypt_and_digest(dek)

    # Encode ciphertext as BASE64URL(Ciphertext)
    b64_encrypted_dek = base64.urlsafe_b64encode(encrypted_dek)

    # Encode Authentication Tag as BASE64URL(Authentication Tag).
    b64_tag = base64.urlsafe_b64encode(tag)

    if config.get_config_by_key('DEV_MODE'):
        logger.debug('Additional authenticated data (aad): '
                     '%s', ascii_b64_protected_header.decode())
        logger.debug('Encrypted dek: "{encrypted_dek.hex()}" (hex), '
                     'tag :"%s" (hex).', tag.hex())

    trace_exit(inspect.currentframe(), (b64_encrypted_dek, b64_tag))
    return b64_encrypted_dek, b64_tag


def _create_jwe_token_json(
        jwe_kid: str,
        b64_protected_header: bytes,
        b64_cek_ciphertext: bytes,
        b64_iv: bytes,
        b64_encrypted_dek: bytes,
        b64_tag: bytes) -> str:
    """
    Create JWE token according to:
    https://tools.ietf.org/html/rfc7516#section-3.3

    Compact Serialization representation:
    BASE64URL(UTF8(JWE Protected Header)) || '.' ||
    BASE64URL(JWE Encrypted Key) || '.' ||
    BASE64URL(JWE Initialization Vector) || '.' ||
    BASE64URL(JWE Ciphertext) || '.' ||
    BASE64URL(JWE Authentication Tag)
    """

    trace_enter(inspect.currentframe())

    jwe = b64_protected_header + b'.' + b64_cek_ciphertext + b'.' + \
        b64_iv + b'.' + b64_encrypted_dek + b'.' + b64_tag

    jwe_token = {
        'kid': jwe_kid,
        'jwe': jwe.decode()
    }

    json_jwe_token = json.dumps(jwe_token)

    logger.debug('Created JWE token: %s', json_jwe_token)

    trace_exit(inspect.currentframe(), json_jwe_token)
    return json_jwe_token


def _get_jwe_protected_header(jwe_kid: str, nonce: str) -> bytes:
    trace_enter(inspect.currentframe())
    # Create JWE protected header (BASE64URL(UTF8(JWE Protected Header)))
    protected_header = {'alg': 'RSA-OAEP', 'enc': 'A256GCM', 'kid': jwe_kid}

    if nonce:
        protected_header['jti'] = nonce

    b64_protected_header = base64.urlsafe_b64encode(
        json.dumps(protected_header).encode('utf-8'))

    trace_exit(inspect.currentframe(), b64_protected_header)
    return b64_protected_header


def get_wrapped_key_as_jwe(
        priv_dek: bytes,
        tenant: str,
        jwe_kid: str,
        nonce: str = '') -> str:
    """Creates JWE."""

    trace_enter(inspect.currentframe())

    logger.info('Creating JWE token for request with kid "%s"...', jwe_kid)

    # Generate a 256 bit AES content encryption key.
    # 32 bytes * 8 = 256 bit -> AES256
    cek = get_random_bytes(32)

    if config.get_config_by_key('DEV_MODE'):
        logger.debug('Generated cek (BYOK AES key): %s (hex)', cek.hex())

    if not (b64_cek_ciphertext :=
            _encrypt_cek_with_key_consumer_key(tenant, jwe_kid, cek)):
        logger.error('Cannot encrypt content encryption key with key consumer'
                     'key of %s/%s.', tenant, jwe_kid)
        trace_exit(inspect.currentframe(), '')
        return ''

    # Generate an initialization vector (IV)
    # for use as input to the data encryption
    # key’s AES wrapping.
    # (BASE64URL(IV)).
    # 12 bytes * 8 = 96 bit
    initialization_vector = get_random_bytes(12)
    b64_iv = base64.urlsafe_b64encode(initialization_vector)

    if config.get_config_by_key('DEV_MODE'):
        logger.debug('Generated IV/Nonce "%s" '
                     '(base64 encoded, bytes).', b64_iv.decode())

    b64_protected_header = _get_jwe_protected_header(jwe_kid, nonce)

    # Encode JWE protected header
    # (ASCII(BASE64URL(UTF8(JWE Protected Header))))
    ascii_b64_protected_header = \
        b64_protected_header.decode().encode('ascii', errors='strict')

    b64_encrypted_dek, b64_tag = \
        _encrypt_dek_with_cek(cek, initialization_vector, priv_dek,
                              ascii_b64_protected_header)

    json_jwe_token = _create_jwe_token_json(
        jwe_kid, b64_protected_header, b64_cek_ciphertext, b64_iv,
        b64_encrypted_dek, b64_tag)

    # cleanup
    del priv_dek
    del cek

    trace_exit(inspect.currentframe(), json_jwe_token)
    return json_jwe_token
