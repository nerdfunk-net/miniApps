import re

import yaml
import logging
import os
import glob
import requests
import json
from collections import defaultdict
from utilities import helper
from businesslogic import your_config_context as user_cc


def to_sot(result, device_fqdn, ciscoconf, raw_device_config, device_defaults, onboarding_config):

    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    directory = os.path.join(BASEDIR, '../conf/tags')
    files = []

    # we read all *.yaml files in our config_context config dir
    for filename in glob.glob(os.path.join(directory, "*.yaml")):
        with open(filename) as f:
            logging.debug("opening file %s to read config_context config" % filename)
            try:
                config = yaml.safe_load(f.read())
                if config is None:
                    logging.error("could not parse file %s" % filename)
                    continue
            except Exception as exc:
                logging.error("could not read file %s; got exception %s" % (filename, exc))
                continue

            name = config.get('name')
            platform = config.get('platform')
            if not config.get('active'):
                logging.debug("config context %s in %s is not active" % (name, filename))
                continue
            if platform is not None:
                if platform != 'all' and platform != device_defaults["platform"]:
                    print("skipping config context %s wrong platform %s" % (name, platform))
                    continue

            logging.debug("config context %s in %s is active" % (name, filename))
            # add filename to our list of files that were processed
            files.append(os.path.basename(filename))

            # get the source. It is either a section or a (named) regular expression
            if 'section' in config['source']:
                device_config = ciscoconf.get_section(config['source']['section'])
            elif 'regex' in config['source']:
                device_config = ciscoconf.get_section_by_regular_expression(config['source']['regex'])
            elif 'object' in config['source']:
                if 'name_pattern' in config['source']:
                    device_config = ciscoconf.get_section_as_dict_by_object(config['source']['object'],
                                                                            config['source']['name_pattern'],
                                                                            config['source']['name_group'])
                else:
                    device_config = ciscoconf.get_section_by_object(config['source']['object'])
            elif 'fullconfig' in config['source']:
                device_config = ciscoconf.get_raw_config()
            else:
                logging.error("unknown source %s" % config['source'])
                continue

            if len(device_config) == 0:
                logging.error("no device config with configured pattern found")
                continue

            #print(json.dumps(device_config, indent=4))
            data = parse_config(device_config, device_fqdn, config, onboarding_config)
            print(data)

    result[device_fqdn]['config_context'] = "Processing config_context %s" % files


def add_tag_to_sot(tag, device_fqdn, key, onboarding_config):
    for scope in tag['scope'].split(","):
        if key is not None and scope == "dcim.interface":
            sot_tag = {
                'name': device_fqdn,
                'interface': key,
                'tag': tag['name']
            }
            helper.send_request("add_tag_to_interface",
                                onboarding_config["sot"]["api_endpoint"],
                                sot_tag)
        if scope == "dcim.device":
            sot_tag = {
                'name': device_fqdn,
                'tag': tag['name']
            }
            helper.send_request("add_tag_to_device",
                                onboarding_config["sot"]["api_endpoint"],
                                sot_tag)


def parse_config(device_config, device_fqdn, config, onboarding_config):

    response = []
    is_list = False
    list_of_list = False

    # check if we have a list of strings or a list of other lists
    # the device_config is always a list
    for block in device_config:
        if isinstance(block, list):
            is_list = True

    # either we have a unnamed block of the config or we have a list of dicts
    # the key of the dict is the name of the matched pattern eg. the interface name
    if not is_list:
        if isinstance(device_config[0], str):
            # this is the case, for example, when we want to parse the entire configuration
            for line in device_config:
                for tag in config['tags']:
                    match = re.search(tag['pattern'], line)
                    if match:
                        add_tag_to_sot(tag, device_fqdn, None, onboarding_config)

        elif isinstance(device_config[0], dict):
            # we have a "named" dict like a list of the interfaces
            for dc_dict in device_config:
                for key, values in dc_dict.items():
                    for line in values:
                        # check if we find the pattern in this line
                        for tag in config['tags']:
                            # a tag config object contains of name, pattern, and scope
                            match = re.search(tag['pattern'], line)
                            if match:
                                add_tag_to_sot(tag, device_fqdn, None, onboarding_config)
    else:
        list_of_list = True
        dc = device_config

    if list_of_list:
        for block in dc:
            data = helper.get_values_from_config_block(block, config['patterns'], config['named_groups'])

