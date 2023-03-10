#!/usr/bin/env python

import argparse
import getpass
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# please set secure salt BEFORE you use this script eg. os.urandom(16)
default_salt = b"mysecretsalt"

# this scripts either:
#   - sets the password for a specified user using the keyring mechanism
#   - encrypts the password using an encryptionkey and the salt configured above
#   - decrypts entered password using the encryptionkey and the salt configured above

yes_choices = ['yes', 'y']
no_choices = ['no', 'n']

parser = argparse.ArgumentParser()
parser.add_argument('--password', type=str, required=False)
parser.add_argument('--set-salt', action='store_true')
parser.add_argument('--decrypt', action='store_true')
parser.add_argument('--encryptionkey', type=str, required=False)
args = parser.parse_args()

if args.password is None and not args.decrypt:
    password = getpass.getpass(prompt="Enter password: ")
else:
    password = args.password

if args.encryptionkey is None:
    encryption_key_ascii = getpass.getpass(prompt="Enter encryptionkey: ")
else:
    encryption_key_ascii = args.encryptionkey

if args.set_salt:
    salt_ascii = getpass.getpass(prompt="Enter salt: ")
    salt_bytes = str.encode(salt_ascii)

else:
    salt_bytes = default_salt

if args.decrypt:
    # get token as base64 and convert it to byte
    token_ascii = input("Enter token: ")
    token_bytes = base64.b64decode(token_ascii)
    encryption_key_bytes = str.encode(encryption_key_ascii)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(encryption_key_bytes))

    f = Fernet(key)
    try:
        print("decrypted: %s" % f.decrypt(token_bytes))
    except Exception as e:
        print("Wrong encryption key or salt %s" % e)

else:
    password_bytes = str.encode(password)
    encrypt_pwd_bytes = str.encode(encryption_key_ascii)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(encrypt_pwd_bytes))
    f = Fernet(key)
    token = f.encrypt(password_bytes)
    print("token: %s" % base64.b64encode(token))
