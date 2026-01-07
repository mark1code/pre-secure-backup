"""
pre-secure-backup : Proxy Re-Encryption Secure Backup
"""

import argparse


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    # encrypt command
    encrypt = subparsers.add_parser("encrypt")

    encrypt.add_argument("--as", dest="user", required=True)
    encrypt.add_argument("--file", dest="file", required=True)
    encrypt.add_argument("--vault", dest="vault", required=True)

    # decrypt command
    decrypt = subparsers.add_parser("decrypt")

    decrypt.add_argument("--as", dest="user", required=True)
    decrypt.add_argument("--id", dest="object_id", required=True)
    decrypt.add_argument("--vault", dest="vault", required=True)
    decrypt.add_argument("--out", dest="out", required=True)

    args = parser.parse_args()

    # test
    print("command:", args.command)

    if args.command == "encrypt":
        print("user:  ", args.user)
        print("file:  ", args.file)
        print("vault: ", args.vault)

    elif args.command == "decrypt":
        print("user:  ", args.user)
        print("id:    ", args.object_id)
        print("vault: ", args.vault)
        print("out:   ", args.out)


if __name__ == "__main__":
    main()