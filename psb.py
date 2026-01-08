"""
pre-secure-backup : Proxy Re-Encryption Secure Backup
"""

import argparse
import os
import json
import uuid
import base64
from envelope import encrypt_object, decrypt_object
from umbral import SecretKey, PublicKey
from umbral import Signer
from umbral import generate_kfrags, reencrypt

# TODO: Move repeated code into its own helper file
def b64e(b):
    return base64.b64encode(b).decode("ascii")

def b64d(s):
    return base64.b64decode(s.encode("ascii"))

def capsule_to_b64(capsule):
    return b64e(bytes(capsule))

def capsule_from_b64(b64):
    from umbral.capsule import Capsule
    return Capsule.from_bytes(b64d(b64))

def cfrag_to_b64(cfrag):
    return b64e(bytes(cfrag))

# Ensures vault (program storage) exists
# Place user keys in users/ and encrypted backups in objects/
def set_vault(vault_path, user):
    os.makedirs(os.path.join(vault_path, "users", user), exist_ok=True)
    os.makedirs(os.path.join(vault_path, "objects"), exist_ok=True)


def get_user_umbral(vault_path, user):
    set_vault(vault_path, user)

    path = os.path.join(vault_path, "users", user, "umbral.json")

    # If their keys exist, load and return
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    
    # Otherwise, create them
    # Encryption pair:
    sk_enc = SecretKey.random()
    pk_enc = sk_enc.public_key()

    # Signing pair
    sk_sign = SecretKey.random()
    pk_verify = sk_sign.public_key()

    # Store secrets as secret bytes
    data = {
        "sk": b64e(sk_enc.to_secret_bytes()),
        "pk": b64e(bytes(pk_enc)),
        "sk_sign": b64e(sk_sign.to_secret_bytes()),
        "pk_verify": b64e(bytes(pk_verify))
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    
    return data


# Gets obj paths
def get_obj_paths(vault_path, obj_id):
    obj_dir = os.path.join(vault_path, "objects")
    bin_path = os.path.join(obj_dir, obj_id + ".bin")
    json_path = os.path.join(obj_dir, obj_id + ".json")
    return obj_dir, bin_path, json_path


# Writes encrypted objects as two files and stores in objects/
# Ciphertext bytes in the binary file
# Metadata for decryption in the JSON file
def write_obj(vault_path, obj_id, ciphertext_bytes, manifest_dict):
    obj_dir, bin_path, json_path = get_obj_paths(vault_path, obj_id)

    with open(bin_path, "wb") as f:
        f.write(ciphertext_bytes)
    
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(manifest_dict, f, indent=2)

# Reads the encrypted object from the vault
def read_obj(vault_path, obj_id):
    obj_dir, bin_path, json_path = get_obj_paths(vault_path, obj_id)

    with open(bin_path, "rb") as f:
        ciphertext_bytes = f.read()

    with open(json_path, "r", encoding="utf-8") as f:
        manifest_dict = json.load(f)
    
    return ciphertext_bytes, manifest_dict

def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Add encrypt keyword
    encrypt = subparsers.add_parser("encrypt")

    encrypt.add_argument("--as", dest="user", required=True)
    encrypt.add_argument("--file", dest="file", required=True)
    encrypt.add_argument("--vault", dest="vault", required=True)

    # Add decrypt keyword
    decrypt = subparsers.add_parser("decrypt")

    decrypt.add_argument("--as", dest="user", required=True)
    decrypt.add_argument("--id", dest="obj_id", required=True)
    decrypt.add_argument("--vault", dest="vault", required=True)
    decrypt.add_argument("--out", dest="out", required=True)

    # Add share keyword
    share = subparsers.add_parser("share")

    share.add_argument("--from", dest="owner", required=True)
    share.add_argument("--to", dest="recipient", required=True)
    share.add_argument("--id", dest="obj_id", required=True)
    share.add_argument("--vault", dest="vault", required=True)

    args = parser.parse_args()

    # Generates a random DEK, encrypts file with AES-GCM, then
    # protects the DEK with Umbral PRE
    if args.command == "encrypt":
        # Read plaintext bytes
        with open(args.file, "rb") as f:
            plaintext = f.read()
      
        umb = get_user_umbral(args.vault, args.user)

        # Encrypt the file with DEK and encrypts the DEK to owner via Umbral
        file_ciphertext, manifest = encrypt_object(args.user, plaintext,
                                                umb["pk"], umb["pk_verify"])

        # Create the output object's cipher and stores in vault/objects/
        obj_id = uuid.uuid4().hex
        write_obj(args.vault, obj_id, file_ciphertext, manifest)
        print(f"Encryption complete.\nObject ID: {obj_id}")

    # Recovers DEK from the owner directly or a delegate then 
    # decrypts the file using AES-GCM
    elif args.command == "decrypt":

        # Load the ciphertext and the manifest
        file_ciphertext, manifest = read_obj(args.vault, args.obj_id)


        # Load requester's Umbral keys for decryption
        umb = get_user_umbral(args.vault, args.user)

        plaintext = decrypt_object(args.user, file_ciphertext, manifest, umb["sk"])
        # Write plaintext
        with open(args.out, "wb") as f:
            f.write(plaintext)
        print(f"Decryption complete.\nOutput in: {args.out}")

    # Generates re-encryption fragments so a proxy can transform
    # access from owner to recipient without revealing
    # plaintext or keys
    elif args.command == "share":
        # Load object for modification
        file_ciphertext, manifest = read_obj(args.vault, args.obj_id)

        umb = manifest["umbral"]

        # Load owner and recipient user key files
        owner_umb = get_user_umbral(args.vault, args.owner)
        recipient_umb = get_user_umbral(args.vault, args.recipient)

        # Deserialise keys
        owner_sk = SecretKey.from_bytes(b64d(owner_umb["sk"]))
        owner_sk_sign = SecretKey.from_bytes(b64d(owner_umb["sk_sign"]))
        signer = Signer(owner_sk_sign)

        recipient_pk = PublicKey.from_bytes(b64d(recipient_umb["pk"]))

        # Deserialise capsule from manifest for proxy transform
        capsule = capsule_from_b64(umb["capsule"])

        # Create re-encryption key fragments
        kfrags = generate_kfrags(
            delegating_sk=owner_sk,
            receiving_pk=recipient_pk,
            signer=signer,
            threshold=1,
            shares=1
        )

        # Proxy re-encryption
        cfrags = [reencrypt(capsule=capsule, kfrag=kfrags[0])]

        # Add delegate to manifest
        if "delegations" not in umb:
            umb["delegations"] = {}

        umb["delegations"][args.recipient] = { "cfrags": [cfrag_to_b64(cfrags[0])] }

        # Re-write (to append) to manifest
        write_obj(args.vault, args.obj_id, file_ciphertext, manifest)
        
        print("Key shared.")

if __name__ == "__main__":
    main()