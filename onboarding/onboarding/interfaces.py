import logging
from businesslogic import your_interfaces as user_int
from utilities import utilities


def to_sot(result, args, device_fqdn, primary_defaults, ciscoconf, onboarding_config):

    """
    loop through all interfaces and update/add item to sot

    Args:
        result:
        args:
        device_fqdn:
        primary_defaults:
        ciscoconf:
        onboarding_config:

    Returns:

    """

    interfaces = ciscoconf.get_interfaces()

    # Port-channels are used as reference by some physical interfaces so
    # add logical interfaces to sot first
    for name in interfaces:
        if 'port-channel' in name.lower():
            add_interface(result,
                          args,
                          device_fqdn,
                          primary_defaults,
                          ciscoconf,
                          name,
                          interfaces[name],
                          onboarding_config)

    # now add physical interface to sot
    for name in interfaces:
        if 'port-channel' not in name.lower():
            add_interface(result,
                          args,
                          device_fqdn,
                          primary_defaults,
                          ciscoconf,
                          name,
                          interfaces[name],
                          onboarding_config)

    # call the user defined business logic
    # the user defined bl can overwrite and modify the device_context
    for name in interfaces:
        logging.debug("calling business logic for %s/%s" % (device_fqdn, name))
        user_int.interface_tags(result,
                                device_fqdn,
                                name,
                                ciscoconf.get_section("interface %s" % name),
                                onboarding_config)


def add_interface(result, args, device_fqdn, primary_defaults, ciscoconf, name, interface, onboarding_config):
    """
    add interface to sot

    Args:
        result:
        args:
        device_fqdn:
        primary_defaults:
        name:
        interface:
        onboarding_config:

    Returns:

    """

    # description may not be null
    description = interface.get('description')
    if description is None:
        description = ""

    data_add_interface = {
        "name": device_fqdn,
        "config": {
            "device": device_fqdn,
            "name": name,
            "type": interface['type'],
            "enabled": 'shutdown' not in interface,
            "description": description
        }
    }

    # check if interface is lag
    if 'lag' in interface:
        data_add_interface['config'].update({
            "lag": "%s%s" % (ciscoconf.get_interface_spelling("port-channel"),
                             interface["lag"]["group"])})

    # setting switchport or trunk
    if 'switchport' in interface:
        mode = interface['switchport']['mode']
        data = {}
        if mode == 'access':
            data = {"mode": "access",
                     "untagged": interface['switchport']['vlan'],
                    "site": args.site or primary_defaults['site']
                    }
        elif mode == 'tagged':
            # this port is either a trunked with allowed vlans (mode: tagged)
            # or a trunk with all vlans mode: tagged-all
            # check if we have allowed vlans
            if 'vlan' in interface['switchport'] and \
                    'range' not in interface['switchport']:
                vlans = ",".join(interface['switchport']['vlan'])
                data = {"mode": "tagged",
                        "tagged": vlans,
                        "site": args.site or primary_defaults['site']
                        }
            else:
                data = {"mode": "tagged-all",
                        "site": args.site or primary_defaults['site']
                        }

        if data is not None:
            data_add_interface['config'].update(data)

    # setting standard tags of interface
    if 'tags' in interface:
        tag_list = ",".join(interface['tags'])
        data_add_interface['config'].update({'tags': tag_list})

    logging.debug("adding %s / %s to sot" % (device_fqdn, name))
    result[device_fqdn][name] = utilities.send_request("interface",
                                                    onboarding_config["sot"]["api_endpoint"],
                                                    data_add_interface)

    # last but not least add address to interface
    if ciscoconf.get_ipaddress(interface['name']) is not None:
        addr = ciscoconf.get_ipaddress(interface['name'])
        data_add_address = {
            "name": device_fqdn,
            "interface": name,
            "address": addr
        }
        logging.debug("adding %s / %s to sot" % (device_fqdn, addr))
        result[device_fqdn][name][addr] = utilities.send_request("addaddress",
                                                              onboarding_config["sot"]["api_endpoint"],
                                                              data_add_address)


def vlans(result, device_fqdn, args, ciscoconf, primary_defaults, onboarding_config):

    # add vlans
    vlans,set_of_vlans = ciscoconf.get_vlans()
    added_vlans = {}

    for vid in vlans:
        data_add_vlan = {
            "vid": vid,
            "name": vlans[vid]['name'],
            "status": "active",
            "site": args.site or primary_defaults['site']
        }
        logging.debug("adding vlan %s of %s to sot" % (vid, device_fqdn))
        result[device_fqdn]['vlan'][vid] = utilities.send_request("addvlan",
                                                               onboarding_config["sot"]["api_endpoint"],
                                                               data_add_vlan)
        # create list of vlans added to the sot
        if result[device_fqdn]['vlan'][vid]['success']:
            added_vlans[vid] = True

    # now add all vlans of the set that were not added to the sot before
    for vid in set_of_vlans:
        if vid not in added_vlans:
            data_add_vlan = {
                "vid": vid,
                "name": "unknown vlan %s" % vid,
                "status": "active",
                "site": args.site or primary_defaults['site']
            }
            logging.debug("adding vlan %s of %s to sot" % (vid, device_fqdn))
            result[device_fqdn]['vlan'][vid] = utilities.send_request("addvlan",
                                                                   onboarding_config["sot"]["api_endpoint"],
                                                                   data_add_vlan)

