from Cryptodome.Hash import SHA1
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
import uuid
import base64
import json
import datetime


# This script implements: https://help.salesforce.com/articleView?id=security_pe_byok_cache_create.htm&type=5

def generate_jwe() -> str:
    now = datetime.datetime.utcnow().strftime('%Y-%m-%d_%H:%M:%S')

    # Generate a 256-bit AES data encryption key. You can use the cryptographically secure method of your choice.
    dek = get_random_bytes(32)  # 32 byte * 8 = 256 bit -> AES256
    with open('output/dek-' + now, 'w') as f:
        f.write(dek.hex())

    # Generate a 256-bit AES content encryption key using a cryptographically secure method.
    cek = get_random_bytes(32)  # 32 byte * 8 = 256 bit -> AES256
    with open('output/cek-' + now, 'w') as f:
        f.write(cek.hex())

    # Generate and download your BYOK-compatible certificate.
    byok = RSA.importKey(open('byok.crt').read())

    # Generate key identifier.
    kid = str(uuid.uuid4())

    # Create the JWE protected header.
    # Encode the JWE protected header as BASE64URL(UTF8(JWE Protected Header)).
    protected_header = {'alg': 'RSA-OAEP', 'enc': 'A256GCM', 'kid': kid}
    b64_protected_header = base64.urlsafe_b64encode(json.dumps(protected_header).encode('utf-8'))

    # Encrypt the content encryption key with the public key from the BYOK certificate using the RSAES-OAEP algorithm.
    # Then encode this encrypted content encryption key as BASE64URL(JWE Encrypted CEK Key).
    cek_cipher = PKCS1_OAEP.new(byok, hashAlgo=SHA1)
    cek_ciphertext = cek_cipher.encrypt(cek)
    b64_cek_ciphertext = base64.urlsafe_b64encode(cek_ciphertext)

    # Generate an initialization vector for use as input to the data encryption key’s AES wrapping.
    # Then encode it in base64url. BASE64URL(JWE Initialization Vector)
    iv = get_random_bytes(16)
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

    BASE64URL(JWE Ciphertext)
    """
    # TODO: Where is the IV? Is the nonce the IV? 😕
    dek_cipher = AES.new(cek, AES.MODE_GCM, nonce=iv, mac_len=16)   # mac_len=16: 128 bit tag
    encrypted_dek, tag = dek_cipher.encrypt_and_digest(pad(dek, AES.block_size))

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

    with open('output/json_jwe_token-' + now + '.json', 'w') as f:
        f.write(json_jwe_token)

    return json_jwe_token
