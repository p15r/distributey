"""
Script to decrypt dek key material for testing purposes.
"""

from Cryptodome.Cipher import AES
import base64


iv = base64.urlsafe_b64decode(b'somebytes')
cek = bytes.fromhex('hex-formatted-string')
aad = b'base64-formated-string'
# if dek is retrieved from JWE token:
# encrypted_dek = base64.urlsafe_b64decode('hex-formatted-string')
# if dek is retrieved from distributey log:
encrypted_dek = bytes.fromhex('hex-formatted-string')
tag = bytes.fromhex('hex-formatted-string')

dek_cipher = AES.new(cek, AES.MODE_GCM, nonce=iv, mac_len=16)
dek_cipher.update(aad)
decrypted_dek = dek_cipher.decrypt_and_verify(encrypted_dek, tag)

print(f'Decrypted dek:\n- raw: {decrypted_dek}\n- '
      f'base64: {base64.b64encode(decrypted_dek).decode()}\nCompare it to dek in Vault.')
