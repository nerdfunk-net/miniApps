import yaml
import requests
import json
import os
import base64
import logging
import re
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from copy import deepcopy


def get_username_and_password(args):
    """
    get username and password from profile
    Args:
        args:

    Returns:
        username: str
        password: str
    """

    """
    credentials are either configured in our config
    or must be entered by the user
    """

    username = None
    password = None

    if args.profile is not None:
        logging.debug("using profile %s" % args.profile)
        profile = args.profile
        account = get_profile(onboarding_config, profile)
        if not account['success']:
            logging.error("could not retrieve username and password")
        else:
            username = account.get('username')
            password = account.get('password')
    if username is None:
        username = input("Username (%s): " % getpass.getuser())
        if username == "":
            username = getpass.getuser()
    elif args.username is not None:
        username = args.username

    if password is None and args.password is None:
        password = getpass.getpass(prompt="Enter password for %s: " % username)
    else:
        if args.password is not None:
            password = args.password

    logging.debug("username=%s, password=%s" % (username, password))

    return username, password


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


def send_request(url, api_endpoint, json_data):
    """
      send request to network abstraction layer
    Args:
        url:
        api_endpoint:
        json_data:

    Returns:
        result (success: true or false, error in case of false)
    """
    #
    # please note: check config.yaml and check if a // is not part of the URL!
    #
    url_request = "%s/onboarding/%s" % (api_endpoint, url)
    r = requests.post(url=url_request, json=json_data)

    if r.status_code != 200:
        return {'success': False, 'logs': 'got status code %i' % r.status_code}
    else:
        # we got a json. parse it and check if we have a success or not
        response = json.loads(r.content)
        if response["success"]:
            return {'success': True,
                    'id': response.get('id'),
                    'log': "%s" % response.get('log')}
        else:
            return {'success': False,
                    'error': "%s " % response.get('error')}


def get_file(api_endpoint, repo, filename, pull=False):
    """

    Args:
        api_endpoint:
        repo:
        filename:
        pull:

    Returns:
        content of file
    """
    r = requests.get(url="%s/get/repo/%s/%s?update=%s" % (api_endpoint,
                                                     repo,
                                                     filename,
                                                     pull))
    if r.status_code != 200:
        logging.error('got status code %i' % r.status_code)
    else:
        # we got a json. parse it and check if we have a success or not
        response = json.loads(r.content)
        if response["success"]:
            content = response['content'].replace("\\n", "\n")
            return content
        else:
            logging.error("error getting file %s/%s; Error: %s" % (repo, filename, response['error']))

    return None


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


def modify_dict(datadict, origin):
    """
    modifies dict from config style to specified dict style
    this is needed by the config_context mechanism

    :param datadict:
    :param origin:
    :return: dict
    """

    # deepcopy before data manipulation
    newdict = deepcopy(datadict)
    transformed = False
    PLACEHOLDER = r"^{{(\S+)}}$"

    for key, value in datadict.items():
        # recurse into nested dicts
        if isinstance(value, dict):
            match = re.match(PLACEHOLDER, key)
            if match:
                transformed = True
                new_key = get_value_from_dict(origin, match.group(1).split("."))
                newdict[new_key] = modify_dict(datadict[key], origin)
                del newdict[key]
            else:
                new_key = key
                newdict[new_key] = modify_dict(datadict[key], origin)
        else:
            match = re.match(PLACEHOLDER, value)
            if match:
                transformed = True
                newdict[key] = get_value_from_dict(origin, match.group(1).split("."))

    return newdict


def process_pattern(pattern, block, value_type):
    """
    check if pattern matches any config line

    Args:
        pattern:
        block:
        value_type:

    Returns:
        values that match
    """
    compiled_pattern = re.compile(pattern)
    if value_type == 'list':
        values = {'values': []}
    else:
        values = {'values': {}}

    # parse data line by line
    for line in block:
        match = compiled_pattern.match(line)
        if match:
            # match.groupdict() returns a list of all named matches
            v = {}
            if len(match.groupdict()) == 0:
                # line matched but without groupdict
                # this is if we want just to know if the line is part of the config
                v.update({line: True})
            for m in match.groupdict():
                v.update({m: match.group(m)})
            if value_type == 'list':
                values['values'].append(v)
            else:
                values['values'] = v

    return values


def get_values_from_config_block(block, configured_patterns, named_groups, name_of_block=None):
    # configured_patterns => config['patterns']
    # named_groups => config['named_groups']
    config_values = {}
    list_of_patterns = []

    # first prepare patterns by replacing the placeholders by the named group
    for configured_pattern in configured_patterns:
        v = {configured_pattern['name']: configured_pattern['pattern']}
        # replace all named_groups in pattern
        for named_group in named_groups:
            v[configured_pattern['name']] = v[configured_pattern['name']].replace(named_group, named_groups[named_group])
            p = {'pattern': v,
                 # if we have no type we use dict as default!
                 'type': configured_pattern.get('type', 'dict')
                 }
            if 'key' in configured_pattern:
                p.update({'key': configured_pattern['key']})
        # after the end of the for loop add p to the list of patterns
        list_of_patterns.append(p)

    # for each pattern get the values for each config block
    for element in list_of_patterns:
        type_wanted = element.get('type', 'dict')
        key_wanted = element.get('key')
        for key, pattern in element['pattern'].items():
            # get all values that match the pattern
            all_values = process_pattern(pattern, block, "list")
            nn_values = len(all_values['values'])
            if nn_values == 0:
                continue

            #print("")
            #print("------")
            #print("type_wanted: %s" % type_wanted)
            #print("key_wanted: %s" % key_wanted)
            #print("key: %s" % key)
            #print("values: %s" % all_values)
            #print("nn_values: %s" % nn_values)
            if key_wanted is None and type_wanted == 'list':
                config_values[key] = all_values['values']
            elif key_wanted is not None and type_wanted == 'list':
                print("XXXX TODO XXXX")
            elif key_wanted is None and type_wanted == 'dict':
                # if nn_values is greater than 1 we should write a warning
                for k, v in all_values['values'][0].items():
                    config_values[key] = v
            elif key_wanted is not None and type_wanted == 'dict':
                # first of all: get new key value
                for value in all_values['values']:
                    # check if key_wanted is a key of a regex
                    # if not use the text of 'key_wanted'
                    new_key = value.get(key_wanted, key_wanted)
                    #if new_key is not None:
                    #    del value[key_wanted]
                    for k, v in value.items():
                        #print("k: %s v: %s" % (k, v))
                        if new_key not in config_values:
                            config_values[new_key] = {}
                        if len(value) == 1:
                            config_values[new_key].update({key: v})
                        else:
                            config_values[new_key].update({k: v})

    if len(config_values) > 0:
        if name_of_block is not None:
            config_values["__name__"] = name_of_block
        #print("config_values: %s" % config_values)
        return config_values

    return None
