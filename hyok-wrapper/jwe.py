from Cryptodome.Hash import SHA1
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
import uuid
import base64
import json
import logging

import vault_backend
import config


# This script implements: https://help.salesforce.com/articleView?id=security_pe_byok_cache_create.htm&type=5

def get_wrapped_key_as_jwe(vault_token: str, kid: str = '', nonce: str = '') -> str:
    logger = logging.getLogger(__name__)

    key = config.get_config_by_key('KEY')

    # Generate a 256-bit AES data encryption key. You can use the cryptographically secure method of your choice.
    # dek = get_random_bytes(32)  # 32 bytes * 8 = 256 bit -> AES256
    dek = vault_backend.get_dynamic_secret(key, vault_token)

    if not dek:
        logger.error('Cannot retrieve dek.')
        return ''

    logger.debug(f'Retrieved dek from Vault: {dek.hex()}')

    # Generate a 256-bit AES content encryption key using a cryptographically secure method.
    # The content encryption key (CEK) can be generated by the key consumer (e.g. Salesforce) or
    # by HYOK-Wrapper itself, which is why the CEK is sometimes also called BYOK key.
    # 32 bytes * 8 = 256 bit -> AES256
    cek = get_random_bytes(32)

    logger.debug(f'Created cek (BYOK AES key): {cek.hex()}')

    # Generate and download your BYOK-compatible certificate.
    # key_consumer_cert: public certificate from key consumer (e.g. Salesforce)
    key_consumer_cert_path = config.get_config_by_key('KEY_CONSUMER_CERT')

    with open(key_consumer_cert_path) as f:
        cert = f.read()

    if not cert:
        logger.error('Cannot read key consumer certificate. Exiting..')
        return ''

    key_consumer_cert = RSA.importKey(cert)

    # Use KID provided by key consumer. If none was given, generate it.
    if not kid:
        kid = str(uuid.uuid4())

    # Create the JWE protected header.
    # Encode the JWE protected header as BASE64URL(UTF8(JWE Protected Header)).
    protected_header = {'alg': 'RSA-OAEP', 'enc': 'A256GCM', 'kid': kid}

    if nonce:
        protected_header['jti'] = nonce

    b64_protected_header = base64.urlsafe_b64encode(json.dumps(protected_header).encode('utf-8'))

    # Encrypt the content encryption key with the public key from the key consumer certificate
    # using the RSAES-OAEP algorithm.
    # Then encode this encrypted content encryption key as BASE64URL(JWE Encrypted CEK Key).
    cek_cipher = PKCS1_OAEP.new(key_consumer_cert, hashAlgo=SHA1)
    cek_ciphertext = cek_cipher.encrypt(cek)
    b64_cek_ciphertext = base64.urlsafe_b64encode(cek_ciphertext)

    # Generate an initialization vector for use as input to the data encryption key’s AES wrapping.
    # Then encode it in base64url. BASE64URL(JWE Initialization Vector)
    # 12 bytes * 8 = 96 bit
    iv = get_random_bytes(12)
    b64_iv = base64.urlsafe_b64encode(iv)

    """
    Wrap your data encryption key with your content encryption key.

        Encode the JWE header as ASCII(BASE64URL(UTF8(JWE Protected Header))).
        Reform authenticated encryption on the data encryption key with the AES GCM algorithm.
            Use the content encryption key as the encryption key, the initialization vector,
            and the Additional Authenticated Data value,
            requesting a 128-bit Authentication Tag output.
        Encode the resulting ciphertext as BASE64URL(Ciphertext).
        Encode the Authentication Tag as BASE64URL(Authentication Tag).
    """
    # pyCryptoDome uses IV and NONCE interchangeably:
    #   - https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html#modern-modes-of-operation-
    #       for-symmetric-block-ciphers

    # Additional authenticated data (aad)
    ascii_b64_protected_header = b64_protected_header.decode().encode('ascii', errors='strict')

    # mac_len=16: 128 bit authentication tag
    dek_cipher = AES.new(cek, AES.MODE_GCM, nonce=iv, mac_len=16)
    dek_cipher.update(ascii_b64_protected_header)
    # TODO: Autom. padding helpful?
    # from Cryptodome.Util.Padding import pad
    # encrypted_dek, tag = dek_cipher.encrypt_and_digest(pad(dek, AES.block_size))
    encrypted_dek, tag = dek_cipher.encrypt_and_digest(dek)

    b64_encrypted_dek = base64.urlsafe_b64encode(encrypted_dek)
    b64_tag = base64.urlsafe_b64encode(tag)

    # https://tools.ietf.org/html/rfc7516#section-3.3:
    #
    # BASE64URL(UTF8(JWE Protected Header)) || '.' ||
    # BASE64URL(JWE Encrypted Key) || '.' ||
    # BASE64URL(JWE Initialization Vector) || '.' ||
    # BASE64URL(JWE Ciphertext) || '.' ||
    # BASE64URL(JWE Authentication Tag)
    jwe = b64_protected_header + b'.' + b64_cek_ciphertext + b'.' + b64_iv + b'.' + b64_encrypted_dek + b'.' + b64_tag

    jwe_token = {
        'kid': kid,
        'jwe': jwe.decode()
    }

    json_jwe_token = json.dumps(jwe_token)

    logger.debug(f'Created jwe token: {json_jwe_token}')

    return json_jwe_token
