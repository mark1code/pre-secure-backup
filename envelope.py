"""
Orchestrates encryption/decryption: generating and applying the DEK, wrapping
it with the KEK, building the JSON manifest, and reversing for decryption.
"""
import os, base64
from aead import encrypt_bytes, decrypt_bytes
# Umbral PRE primitives
from umbral import SecretKey, PublicKey
from umbral import encrypt, decrypt_original, decrypt_reencrypted

# Fragments for decryption after delegation
from umbral import CapsuleFrag

# Encoding helper functions for r/w JSON
def b64_encode(b):
    return base64.b64encode(b).decode("ascii")

def b64_decode(s):
    return base64.b64decode(s.encode("ascii"))

# Umbral serialisation helpers
def pk_from_b64(b64):
    return PublicKey.from_bytes(b64_decode(b64))

def sk_from_b64(b64):
    return SecretKey.from_bytes(b64_decode(b64))

def capsule_to_b64(capsule):
    return b64_encode(bytes(capsule))

def capsule_from_b64(b64):
    from umbral.capsule import Capsule
    return Capsule.from_bytes(b64_decode(b64))

# Makes a random DEK (256 bits)
def make_dek():
    return os.urandom(32)

"""
# Encrypts the DEK with user's KEK
def wrap_dek(kek, dek):
    return encrypt_bytes(kek, dek)

# Decrypts KEK
def unwrap_dek(kek, wrap_nonce, ct_wrapped_dek):
    return decrypt_bytes(kek, wrap_nonce, ct_wrapped_dek)
"""

# Handles the encryption of a file
def encrypt_object_old(owner, plaintext, kek):
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

def encrypt_object(owner, plaintext, owner_pk_b64, owner_verify_pk_b64):
    dek = make_dek()
    # Encrypt the data with AES-GCM
    file_nonce, file_ciphertext = encrypt_bytes(dek, plaintext)

    # Encrypt/encapsulate to the owner with Umbral
    owner_pk = pk_from_b64(owner_pk_b64)
    capsule, dek_ciphertext = encrypt(owner_pk, dek)

    # Add metadata required for decryption
    manifest = {
        "version": 2,
        "owner": owner,
        "aead": "AESGCM",
        "file_nonce": b64_encode(file_nonce),

        # Umbral for who can recover the DEK
        "umbral": {
            "owner_pk": owner_pk_b64,
            "owner_verify_pk": owner_verify_pk_b64,
            "capsule": capsule_to_b64(capsule),
            "dek_ct": b64_encode(dek_ciphertext),

            # For sharing/who can access
            "delegations": {}
        }
    }

    return file_ciphertext, manifest


# Handles the decryption of a file
def decrypt_object_old(requester, file_ciphertext, manifest, kek):
    if manifest["owner"] != requester:
        raise PermissionError("User unauthorised (until delegation gets added)")
    
    file_nonce = b64_decode(manifest["file_nonce"])
    wrap_nonce = b64_decode(manifest["wrap_nonce"])
    ct_wrapped_dek = b64_decode(manifest["wrapped_dek"])

    dek = unwrap_dek(kek, wrap_nonce, ct_wrapped_dek)
    plaintext = decrypt_bytes(dek, file_nonce, file_ciphertext)
    return plaintext

def decrypt_object(requester, file_ciphertext, manifest, requester_sk_b64):
    # Load nonce
    file_nonce = b64_decode(manifest["file_nonce"])

    # Load umbral details
    umb = manifest["umbral"]
    capsule = capsule_from_b64(umb["capsule"])
    dek_ct = b64_decode(umb["dek_ct"])

    owner = manifest["owner"]
    owner_pk = pk_from_b64(umb["owner_pk"])

    requester_sk = sk_from_b64(requester_sk_b64)

    # Case 1, if requester is owner
    if requester == owner:
        dek = decrypt_original(requester_sk, capsule, dek_ct)
    
    # Case 2, a delegate
    else:
        delegations = umb.get("delegations", {})
        if requester not in delegations:
            raise PermissionError("User unauthorised (not delegated)")
        
        # Get capsule fragments and deserialise
        cfrag_b64_list = delegations[requester]["cfrags"]
        cfrags = [CapsuleFrag.from_bytes(b64_decode(x)) for x in cfrag_b64_list]

        # Authentication/verification
        verifying_pk = pk_from_b64(umb["owner_verify_pk"])
        receiving_pk = requester_sk.public_key()

        verified_cfrags = [
            cfrag.verify(capsule,
                verifying_pk = verifying_pk,
                delegating_pk=owner_pk,
                receiving_pk=receiving_pk)
            for cfrag in cfrags
        ]
        
        # Delegate recovers DEK via PRE
        dek = decrypt_reencrypted(
            receiving_sk=requester_sk,
            delegating_pk=owner_pk,
            capsule=capsule,
            verified_cfrags=verified_cfrags,
            ciphertext=dek_ct
        )

    # Decrypt the file using the recovered symmetric key
    plaintext = decrypt_bytes(dek, file_nonce, file_ciphertext)
    return plaintext