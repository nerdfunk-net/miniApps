import logging
from businesslogic import your_device as user_bc_device
from utilities import helper


def to_sot(result, args, device_fqdn, device_facts, raw_device_config, primary_defaults, onboarding_config):

    # note: internally we use the slug for getting site, device_type or platform
    site = args.site or primary_defaults['site']
    device_role = args.role or primary_defaults['role']
    manufacturer = args.manufacturer or primary_defaults['manufacturer']
    platform = args.platform or primary_defaults['platform']
    device_type = args.device_type or primary_defaults['device_type']

    if 'model' in device_facts:
        device_type = device_facts['model']

    # check if serial_number is list or string. We need {'12345','12345'}
    if isinstance(device_facts["serial_number"], list):
        sn = ', '.join(map(str, device_facts["serial_number"]))
    else:
        sn = device_facts["serial_number"]

    # add device to sot
    data_add_device = {
        "name": device_fqdn,
        "config": {
            "name": device_fqdn,
            "site": site.lower(),
            "device_role": device_role.lower(),
            "device_type": device_type.lower(),
            "manufacturer": manufacturer.lower(),
            "platform": platform.lower(),
            "serial": sn,
            "status": args.status or primary_defaults['status']
        }
    }
    # send_request is our helper function to call the network abstraction layer
    logging.debug("adding device %s (%s) to sot" % (device_fqdn, device_type))
    result[device_fqdn]['device'] = helper.send_request("device",
                                                        onboarding_config["sot"]["api_endpoint"],
                                                        data_add_device)

    # call the user defined business logic
    # the user defined bl can overwrite and modify the device_context
    logging.debug("calling business logic of device %s to sot" % device_fqdn)
    user_bc_device.device(result, device_fqdn, raw_device_config, onboarding_config)


def primary_ip(result, device_fqdn, primary_address, ciscoconf, onboarding_config):

    # set primary IP/Interface of device
    # check if the primary IP has the wrong format
    if '/' in primary_address:
        primary_address_host = primary_address.split('/')[0]
    else:
        primary_address_host = primary_address
    interface_name = ciscoconf.get_interface_name_by_address(primary_address_host)
    interface = ciscoconf.get_interface(interface_name)

    # if we have the right mask of the interface/ip we use this instead of a /32
    if 'ipv4' in interface and 'cidr' in interface['ipv4']:
        primary_address = interface['ipv4']['cidr']

    if interface is not None and interface_name is not None:
        new_addr = {"primary_ip4": {
                        "primary_ip4": primary_address,
                        "interface": interface_name,
                        "interface_type": interface['type'],
                        "description": interface['description']}
                    }
        data_set_primary = {
            "name": device_fqdn,
            "config": new_addr
        }
        logging.debug("setting primary IP of %s to %s in sot" % (device_fqdn, primary_address))
        result[device_fqdn]['primary_ip'] = helper.send_request("updatedevice",
                                                                onboarding_config["sot"]["api_endpoint"],
                                                                data_set_primary)
    else:
        result[device_fqdn]['primary_ip'] = \
            "no primary interface found; please set primary IP manually"


def backup_config(result, device_fqdn, raw_device_config, onboarding_config):

    config = {
        'repo': 'config_backup',
        'filename': device_fqdn,
        'content': raw_device_config,
        'action': 'overwrite',
        'pull': False,
    }

    newconfig = {
        "config": config
    }

    result[device_fqdn]['backup'] = helper.send_request("editfile",
                                                        onboarding_config["sot"]["api_endpoint"],
                                                        newconfig)

