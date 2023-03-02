#!/usr/bin/env python

import argparse
import sys
import pytricia
import yaml
import socket
import os
import json
import logging
from dotenv import load_dotenv, dotenv_values
from utilities.ciscoconfig import DeviceConfig
from utilities import utilities
from utilities import devicemanagement as dm
from collections import defaultdict
from onboarding import interfaces as onboarding_interfaces
from onboarding import devices as onboarding_devices
from onboarding import config_context as onboarding_config_context
from onboarding import cables as onboarding_cables
from onboarding import facts as facts
from onboarding import tags as onboarding_tags

# set default config file to your needs
default_config_file = "./conf/onboarding/config.yaml"


# this defaultdict enables us to use infinite numbers of arguments
def inf_defaultdict():
    return defaultdict(inf_defaultdict)


def onboarding(result, device_facts, raw_device_config, onboarding_config, device_defaults):

    # get cisco config object and parse config
    # ciscoconfparse expects the device config as lines
    ciscoconf = DeviceConfig(raw_device_config)

    # we need the fqdn of the device
    if device_facts is not None and 'fqdn' in device_facts:
        device_fqdn = device_facts['fqdn']
    else:
        # get fqdn from config instead
        device_fqdn = ciscoconf.get_fqdn()

    # get primary address of the device
    # the primary address is the ip address of the 'default' interface.
    # in most cases this is the Loopback or the Management interface
    # the interfaces we look at can be configured in our onboarding config
    pa = get_primary_address(device_fqdn,
                             onboarding_config['onboarding']['defaults']['interface'],
                             ciscoconf)
    if pa is not None:
        primary_address = pa['config']['primary_ip4']
        logging.debug("primary address %s" % primary_address)
    else:
        # no primary interface found. Get IP of the device
        logging.info("no primary ip found using %s" % device_facts['args.device'])
        primary_address = socket.gethostbyname(device_facts['args.device'])

    # check if we have all necessary defaults
    list_def = ['site', 'role', 'device_type', 'manufacturer', 'platform', 'status']
    for i in list_def:
        if i not in device_defaults:
            logging.critical("%s missing. Please add %s to your default or set as arg" % (i, i))
            print("%s missing. Please add %s to your default or set as arg" % (i, i))
            return result

    logging.debug("device_defaults are: %s" % device_defaults)

    # set tags on interface
    if 'tags' in onboarding_config['onboarding']:
        if 'interfaces' in onboarding_config['onboarding']['tags']:
            for tag in onboarding_config['onboarding']['tags']['interfaces']:
                ciscoconf.tag_interfaces(tag, onboarding_config['onboarding']['tags']['interfaces'][tag])

    # now lets start the onboarding process
    # first of all import the device to our sot
    if args.onboarding:
        onboarding_devices.to_sot(result,
                                  args,
                                  device_fqdn,
                                  device_facts,
                                  raw_device_config,
                                  device_defaults,
                                  onboarding_config)

    # we add the vlans before adding the physical or virtual interfaces
    # because some interfaces may be access vlans
    if args.vlans:
        onboarding_interfaces.vlans(result,
                                    device_fqdn,
                                    args,
                                    ciscoconf,
                                    device_defaults,
                                    onboarding_config)

    # now add interfaces to sot
    if args.interfaces:
        onboarding_interfaces.to_sot(result,
                                     args,
                                     device_fqdn,
                                     device_defaults,
                                     ciscoconf,
                                     onboarding_config)

    # we are now able to set the primary IP
    # the primary IP requires the device (of course) and the
    # interface the IP address if configured on
    if args.onboarding:
        onboarding_devices.primary_ip(result,
                                      device_fqdn,
                                      primary_address,
                                      ciscoconf,
                                      onboarding_config)

    if args.tags:
        onboarding_tags.to_sot(result,
                               device_fqdn,
                               ciscoconf,
                               raw_device_config,
                               device_defaults,
                               onboarding_config)

    # now the most import part: the config_context
    # do your own business logic in the "businesslogic" subdir
    if args.config_context:
        onboarding_config_context.to_sot(result,
                                         device_fqdn,
                                         ciscoconf,
                                         raw_device_config,
                                         device_defaults,
                                         onboarding_config)

    # at last do a backup of the running config
    if args.backup:
        onboarding_devices.backup_config(result,
                                         device_fqdn,
                                         raw_device_config,
                                         onboarding_config)

    return result


def get_primary_address(device_fqdn, interfaces, cisco_config):
    for iface in interfaces:
        if cisco_config.get_ipaddress(iface) is not None:
            new_addr = {"primary_ip4": cisco_config.get_ipaddress(iface)}
            return {
                "name": device_fqdn,
                "config": new_addr,
                "interface": iface
            }

    return None


def get_prefix_path(prefixe, ip):
    prefix_path = []
    pyt = pytricia.PyTricia()

    # build pytricia tree
    for prefix_ip in prefixe:
        pyt.insert(prefix_ip, prefix_ip)

    prefix = pyt.get(ip)
    prefix_path.append(prefix)

    parent = pyt.parent(prefix)
    while (parent):
        prefix_path.append(parent)
        parent = pyt.parent(parent)
    return prefix_path[::-1]


def get_prefix_defaults(prefixe, ip):
    if prefixe is None:
        return {}

    prefix_path = get_prefix_path(prefixe, ip)
    defaults = {}

    for prefix in prefix_path:
        defaults.update(prefixe[prefix])

    # if the user sets parameter overwrite default values
    if args.platform is not None:
        defaults["platform"] = args.platform
    if args.site is not None:
        defaults["site"] = args.site
    if args.role is not None:
        defaults["role"] = args.role
    if args.device_type is not None:
        defaults["device_type"] = args.device_type
    if args.manufacturer is not None:
        defaults["manufacturer"] = args.manufacturer

    return defaults


def get_device_config(conn, args):
    """
        get device config
    Args:
        conn: connection to device
        args: command line arguments

    Returns:
        device config: str
    """

    # either we read the device config from a file or we
    # connect to the device and get the running config
    if args.deviceconfig is not None:
        logging.debug("reading config from file args.deviceconfig")
        # read device config from file
        # XXX noch einmal checken ob das geht
        with open(args.deviceconfig, 'r') as f:
            return f.read()
    elif conn is not None:
        """
        read the running config from the device
        we need the username and password.
        """
        logging.debug("getting config")
        return dm.get_config(conn, "running-config")
    else:
        print("problem getting config")
        logging.critical("problem getting config")
        return None


if __name__ == "__main__":

    """
    There is only on mandatory argument. We need the device config or the device.
    The other arguments can override the default values configured
    in our config file.
    """
    parser = argparse.ArgumentParser()
    # what to do
    parser.add_argument('--onboarding', action='store_true')
    parser.add_argument('--interfaces', action='store_true')
    parser.add_argument('--vlans', action='store_true')
    parser.add_argument('--cables', action='store_true')
    parser.add_argument('--config-context', action='store_true')
    parser.add_argument('--tags', action='store_true')
    parser.add_argument('--backup', action='store_true')
    parser.add_argument('--show-facts', action='store_true')
    parser.add_argument('--show-config', action='store_true')

    # the user can enter a different config file
    parser.add_argument('--config', type=str, required=False)
    # we need the config. The config can be read or retrieved
    # from the device
    parser.add_argument('--deviceconfig', type=str, required=False, help="device config")
    parser.add_argument('--primary-ip', type=str, required=False, help="primary IP if deviceconfig is used")
    parser.add_argument('--device', type=str, required=False, help="hostname or IP address of device")
    parser.add_argument('--list', type=str, required=False, help="filename to get a list of devices")
    parser.add_argument('--port', type=int, default=22, required=False)
    # we need username and password if the config is retrieved by the device
    # credentials can be configured using a profile
    # have a look at the config file
    parser.add_argument('--username', type=str, required=False)
    parser.add_argument('--password', type=str, required=False)
    parser.add_argument('--profile', type=str, required=False)
    # we need some mandatory properties
    # either these properties are part of the prefixe
    parser.add_argument('--prefixe', type=str, required=False)
    parser.add_argument('--repo', type=str, required=False)
    # or the properties must be specified using the following args
    parser.add_argument('--site', type=str, required=False)
    parser.add_argument('--role', type=str, required=False)
    parser.add_argument('--manufacturer', type=str, required=False)
    parser.add_argument('--device_type', type=str, required=False)
    parser.add_argument('--platform', type=str, default="ios", required=False)
    parser.add_argument('--status', type=str, required=False)

    args = parser.parse_args()
    # set defaults
    prefixe = None
    device_facts = None

    # Get the path to the directory this file is in
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    # Connect the path with the '.env' file name
    load_dotenv(os.path.join(BASEDIR, '.env'))
    # you can get the env variable by using var = os.getenv('varname')

    # read onboarding config
    if args.config is not None:
        config_file = args.config
    else:
        config_file = default_config_file
    onboarding_config = utilities.read_config(config_file)

    # set logging
    cfg_loglevel = utilities.get_value_from_dict(onboarding_config, ['onboarding','logging','level'])
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
    log_format = utilities.get_value_from_dict(onboarding_config, ['onboarding','logging','format'])
    if log_format is None:
        log_format = '%(asctime)s %(levelname)s:%(message)s'
    logfile = utilities.get_value_from_dict(onboarding_config, ['onboarding','logging','filename'])
    logging.basicConfig(level=loglevel,
                        format=log_format,
                        filename=logfile)
    logging.debug("config %s read" % config_file)

    """
    get username and password
    """
    if args.deviceconfig is None:
        username, password = utilities.get_username_and_password(args)

    # get default values of prefixes. This is needed only once
    repo = args.repo or onboarding_config['files']['prefixe']['repo']
    filename = args.prefixe or onboarding_config['files']['prefixe']['filename']
    logging.debug("reading %s from %s" % (filename, repo))
    prefixe_str = utilities.get_file(onboarding_config["sot"]["api_endpoint"], repo, filename)
    if prefixe_str is None:
        logging.error("could not load prefixe.")
        print("could not load prefixe.")
        sys.exit(-1)

    try:
        prefixe_yaml = yaml.safe_load(prefixe_str)
        if prefixe_yaml is not None and 'prefixe' in prefixe_yaml:
            prefixe = prefixe_yaml['prefixe']
    except Exception as exc:
        logging.error("got exception: %s" % exc)
        print("got exception: %s" % exc)
        sys.exit(-1)

    """
    we have the constant values. Now get the config of each device and call onboarding
    """

    # result contains all the results of our onboarding run
    # result is a defaultdict of nested defaultdicts
    # in this case you can use result['one']['two']['three'] = "four"
    result = inf_defaultdict()
    # devicelist is the list of devices
    devicelist = []
    # conn is the connection to a device
    conn = None

    # add list of devices to our list of devices
    if args.list is not None:
        with open(args.list) as f:
            devicelist = f.read().splitlines()

    # add devices from cli to list
    if args.device is not None:
        devicelist += args.device.split(',')

    # if the user uses args.deviceconfig we read the config
    # instead of adding devices to our list of devices
    # this parameter can only be used with one config, also one device
    if args.deviceconfig is not None:
        # config file specified
        if args.onboarding or args.interfaces or args.vlans or args.config_context:
            logging.debug("configfile specified")
            # get defaults
            device_ip = socket.gethostbyname(args.primary_ip)
            device_defaults = get_prefix_defaults(prefixe, device_ip)
            # get config
            device_config = get_device_config(None, args)
            if device_config is None:
                logging.error("could not read device config")
                print("could not read device config")
                sys.exit(-1)
            # we have no device facts; so set primary IP manually
            device_facts = {
                "vendor": "cisco",
                "os_version": "version 7.0(7)N1(1)",
                "serial_number": [
                    "AAAAA"
                ],
                "model": "Nexus-5596",
                "hostname": "HOSTNAME",
                "fqdn": "HOSTNAME.lab.local",
                "args.device": args.primary_ip
            }
            onboarding(result,
                       device_facts,
                       device_config,
                       onboarding_config,
                       device_defaults)
    else:
        for device in devicelist:
            logging.debug("processing %s" % device)
            # check and set platform
            try:
                device_ip = socket.gethostbyname(device)
            except Exception as esc:
                logging.error("could not resolve ip address; %s" % esc)
                continue
            device_defaults = get_prefix_defaults(prefixe, device_ip)
            platform = device_defaults.get("platform")
            if args.platform is not None:
                platform = args.platform
            if platform is None:
                logging.error("no platform for %s configured or specified" % device)
                continue
            logging.debug("platform of %s is %s" % (device, platform))
            # get connection
            conn = dm.open_connection(device, username, password, platform, args.port)
            # retrieve facts like fqdn
            device_facts = facts.get_facts(conn, result, device_defaults)
            device_facts['args.device'] = device
            # retrieve device config as list of strings
            device_config = get_device_config(conn, args)
            if device_config is None:
                logging.error("could not retrieve device config")
                conn.close()
                continue
            conn.close()

            if args.show_facts:
                print(json.dumps(dict(device_facts), indent=4))
                continue
            if args.show_config:
                print(device_config)
                continue
            ret = onboarding(result,
                             device_facts,
                             device_config,
                             onboarding_config,
                             device_defaults)
            result.update(ret)

    # after adding all devices to our sot we add the cables
    if args.cables:
        for device in devicelist:
            logging.debug("adding cables of %s to sot" % device)
            conn = dm.open_connection(device,
                                      username,
                                      password,
                                      args.platform,
                                      args.port)
            if device_facts is None:
                device_facts = facts.get_facts(conn, result, device_defaults)
                device_facts['args.device'] = device
            onboarding_cables.to_sot(result,
                                     conn,
                                     device_facts,
                                     device_defaults,
                                     onboarding_config)
            conn.close()

    target = utilities.get_value_from_dict(onboarding_config,
                                        ['onboarding','logging','result'])
    if target == 'stdout':
        if result:
            print(json.dumps(dict(result), indent=4))
    else:
        with open(target, 'w') as f:
            f.write(json.dumps(dict(result),indent=4))

#
# Todo:
#  - vlan hinzufuegen wenn es noch nicht als vlan im nautobot ist (switch) evtl. mit arg als parameter!
#  - svi hat falschen typ (other, sollte virtual sein)
