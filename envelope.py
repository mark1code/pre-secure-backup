"""
Orchestrates encryption/decryption: generating and applying the DEK, wrapping
it with the KEK, building the JSON manifest, and reversing for decryption.
"""
import os, base64
from aead import encrypt_bytes, decrypt_bytes

# Encoding helper functions for r/w JSON
def b64_encode(b):
    return base64.b64encode(b).decode("ascii")

def b64_decode(s):
    return base64.b64decode(s.encode("ascii"))

# Makes a random DEK (256 bits)
def make_dek():
    return os.urandom(32)

# Encrypts the DEK with user's KEK
def wrap_dek(kek, dek):
    return encrypt_bytes(kek, dek)

# Decrypts KEK
def unwrap_dek(kek, wrap_nonce, ct_wrapped_dek):
    return decrypt_bytes(kek, wrap_nonce, ct_wrapped_dek)

# Handles the encryption of a file
def encrypt_object(owner, plaintext, kek):
    dek = make_dek()
    # Encrypt the data
    file_nonce, file_ciphertext = encrypt_bytes(dek, plaintext)
    # Encrypt the symmetric key
    wrap_nonce, ct_wrapped_dek = wrap_dek(kek, dek)

    # Add metadata required for decryption
    manifest = {
        "version": 1,
        "owner": owner,
        "aead": "AESGCM",
        "file_nonce": b64_encode(file_nonce),
        "wrap_nonce": b64_encode(wrap_nonce),
        "wrapped_dek": b64_encode(ct_wrapped_dek),
    }
    return file_ciphertext, manifest

# Handles the decryption of a file
def decrypt_object(requester, file_ciphertext, manifest, kek):
    if manifest["owner"] != requester:
        raise PermissionError("User unauthorised (until delegation gets added)")
    
    file_nonce = b64_decode(manifest["file_nonce"])
    wrap_nonce = b64_decode(manifest["wrap_nonce"])
    ct_wrapped_dek = b64_decode(manifest["wrapped_dek"])

    dek = unwrap_dek(kek, wrap_nonce, ct_wrapped_dek)
    plaintext = decrypt_bytes(dek, file_nonce, file_ciphertext)
    return plaintext