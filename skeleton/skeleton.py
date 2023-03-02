#!/usr/bin/env python

import argparse
import logging
import os
import getpass
import json
from utilities import utilities
from utilities import devicemanagement as dm
from dotenv import load_dotenv, dotenv_values


BASEDIR = os.path.abspath(os.path.dirname(__file__))
DEFAULT_CONFIG_FILE = "./conf/skeleton.yaml"


"""
Filter:
   - name=devicename
     role=rolename
     model=device type slug
"""


def get_username_and_password(args):
    username = None
    password = None

    if args.profile is not None:
        logging.debug("using profile %s" % args.profile)
        profile = args.profile
        account = utilities.get_profile(skeleton_config, profile)
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


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    # what to do
    parser.add_argument('--device', type=str, required=False)
    parser.add_argument('--filter', type=str, required=False)
    # where to save
    parser.add_argument('--repo', type=str, required=False)
    # the user can enter a different config file
    parser.add_argument('--config', type=str, required=False)
    # we need username and password to connect to the device
    # credentials can be configured using a profile
    # have a look at the config file
    parser.add_argument('--username', type=str, required=False)
    parser.add_argument('--password', type=str, required=False)
    parser.add_argument('--profile', type=str, required=False)

    args = parser.parse_args()

    # Connect the path with the '.env' file name
    load_dotenv(os.path.join(BASEDIR, '.env'))
    # you can get the env variable by using var = os.getenv('varname')

    # read config
    if args.config is not None:
        config_file = args.config
    else:
        config_file = DEFAULT_CONFIG_FILE
    skeleton_config = utilities.read_config(config_file)

    # set logging
    cfg_loglevel = utilities.get_value_from_dict(skeleton_config, ['skeleton', 'logging', 'level'])
    if cfg_loglevel == 'debug':
        loglevel = logging.DEBUG
    elif cfg_loglevel == 'info':
        loglevel = logging.INFO
    elif cfg_loglevel == 'critical':
        loglevel = logging.CRITICAL
    elif cfg_loglevel == 'error':
        loglevel = logging.ERROR
    elif cfg_loglevel == 'none':
        loglevel = 100
    else:
        loglevel = logging.NOTSET
    log_format = utilities.get_value_from_dict(skeleton_config, ['skeleton', 'logging', 'format'])
    if log_format is None:
        log_format = '%(asctime)s %(levelname)s:%(message)s'
    logfile = utilities.get_value_from_dict(skeleton_config, ['skeleton', 'logging', 'filename'])
    logging.basicConfig(level=loglevel,
                        format=log_format,
                        filename=logfile)
    logging.debug("config %s read" % config_file)

    # get username and password
    username, password = get_username_and_password(args)

    if args.filter is not None:
        filter = "/?%s" % args.filter
    else:
        filter = ""
    devices = dm.get_devices(skeleton_config["sot"]["api_endpoint"], filter)
    device_list =[]
    for device in devices["devices"]:
        device_list.append(device["primary_ip4"]["address"].split("/")[0])

    print(device_list)
