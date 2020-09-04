"""
Script to decrypt dek key material for testing purposes.
"""

from Cryptodome.Cipher import AES
import base64


iv = base64.urlsafe_b64decode(b'somebytes')
cek = bytes.fromhex('hex-formatted-string')
aad = b'base64-formated-string'
encrypted_dek = bytes.fromhex('hex-formatted-string')
tag = bytes.fromhex('hex-formatted-string')

dek_cipher = AES.new(cek, AES.MODE_GCM, nonce=iv, mac_len=16)
dek_cipher.update(aad)
data = dek_cipher.decrypt_and_verify(encrypted_dek, tag)

print(f'Decrypted dek:\n- raw: {data}\n- base64: {base64.b64encode(data).decode()}\nCompare it to dek in Vault.')
