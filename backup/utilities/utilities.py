import os
import base64
import yaml
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def read_config(filename):
    """
    read config from file
    Returns: json
    """
    with open(filename) as f:
        return yaml.safe_load(f.read())


def get_value_from_dict(dictionary, keys):
    if dictionary is None:
        return None

    nested_dict = dictionary

    for key in keys:
        try:
            nested_dict = nested_dict[key]
        except KeyError as e:
            return None
        except IndexError as e:
            return None
        except TypeError as e:
            return nested_dict

    return nested_dict


def decrypt_password(password):
    """

    decrypts base64 password that is stored in our yaml config

    Args:
        password:

    Returns: clear password

    """
    # prepare salt
    salt_ascii = os.getenv('SALT')
    salt_bytes = str.encode(salt_ascii)

    # prepare encryption key, we need it as bytes
    encryption_key_ascii = os.getenv('ENCRYPTIONKEY')
    encryption_key_bytes = str.encode(encryption_key_ascii)

    # get password as base64 and convert it to bytes
    password_bytes = base64.b64decode(password)

    # derive key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(encryption_key_bytes))

    f = Fernet(key)
    # decrypt and return
    try:
        return f.decrypt(password_bytes).decode("utf-8")
    except:
        return None


def get_profile(config, profilename='default'):
    """
        gets profile (username and password) from config
    Args:
        config:
        profilename:

    Returns: account as dict

    """

    result = {}
    clear_password = None

    username = get_value_from_dict(config, ['accounts',
                                            'devices',
                                            profilename,
                                            'username'])
    password = get_value_from_dict(config, ['accounts',
                                            'devices',
                                            profilename,
                                            'password'])

    if password is not None:
        clear_password = decrypt_password(password)

    if clear_password is None:
        return {'success': False, 'reason': 'wrong password'}
    else:
        return {'success': True, 'username': username, 'password': clear_password}
