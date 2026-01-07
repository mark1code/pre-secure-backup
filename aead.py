"""
AEAD primitives: AES-GCM encrypt/decrypt for raw bytes
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Encrypt raw bytes via AES-GCM
def encrypt_bytes(key, plaintext, aad=None):
    if aad is None:
        aad = b""
    # 12 byte (96 bit) nonce
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    return nonce, ciphertext

# Decrypt raw bytes via AES-GCM
def decrypt_bytes(key, nonce, ciphertext, aad=None):
    if aad is None:
        aad = b""

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

    return plaintext
    
