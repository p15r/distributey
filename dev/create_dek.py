# DEK: Data Encryption Key (key material to be delivered to consumer for data encryption)

# Generating an AES256 key does not mean to use the AES algo. It simply means to create a key
# conform to use with AES256 encryption, e.g.: key = get_random_bytes(32)  # 32byte * 8 = 256bit -> AES256

import base64

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Util.Padding import pad

password = get_random_bytes(32)  # 32byte * 8 = 256bit -> AES256
# password = 'password_will_be_padded'
salt = get_random_bytes(8)
iv = b'0123456789abcdef'
plain_text = b'Hello World!'

key = PBKDF2(password, salt, dkLen=16, count=1000)

print(f'🔓 Plain text: {plain_text.decode()}')
print(f'🔑 Password (hex): {password.hex()}')
print(f'🧂 Salt (hex): {salt.hex()}')
print(f'🔑 Key (derived from pwd; pbkdf2; hex): {key.hex()}')
print(f'🔑 IV (hex): {iv.hex()}')

cipher = AES.new(key, AES.MODE_CBC, iv=iv)
encrypted_data = cipher.encrypt(pad(plain_text, AES.block_size))
b64_encrypted_data = base64.b64encode(encrypted_data)

print(f'🔒 Encrypted data (base64 encoded): {b64_encrypted_data.decode()}')

# decrypt
# from Cryptodome.Util.Padding import unpad
# cipher = AES.new(key, AES.MODE_CBC, iv=iv)
# encrypted_data = base64.b64decode(b64_encrypted_data)
# original_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
# print(f'🔓 Original data: {original_data.decode()}')
