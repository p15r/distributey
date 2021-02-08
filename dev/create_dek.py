"""
DEK: Data Encryption Key
(key material to be delivered to key consumer for data encryption)
"""

import base64

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Util.Padding import pad
from Cryptodome.Util.Padding import unpad

# 32byte * 8 = 256bit -> AES256
password = get_random_bytes(32)
# password = 'user set password will be padded'

salt = get_random_bytes(8)
init_vector = b'0123456789abcdef'
plain_text = b'Hello World!'

key = PBKDF2(password, salt, dkLen=16, count=1000)

print(f'🔓 Plain text: {plain_text.decode()}')
print(f'🔑 Password (hex): {password.hex()}')
print(f'🧂 Salt (hex): {salt.hex()}')
print(f'🔑 Key (derived from password; pbkdf2; hex): {key.hex()}')
print(f'🔑 IV (hex): {init_vector.hex()}')

# encrypt
cipher = AES.new(key, AES.MODE_GCM, nonce=init_vector)
cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
b64_cipher_text = base64.b64encode(cipher_text)

print(f'🔒 Encrypted data (base64): {b64_cipher_text.decode()}')

# decrypt
cipher = AES.new(key, AES.MODE_GCM, nonce=init_vector)
cipher_text = base64.b64decode(b64_cipher_text)
decrypted_data = unpad(cipher.decrypt(cipher_text), AES.block_size)
print(f'🔓 Original plain text: {decrypted_data.decode()}')
