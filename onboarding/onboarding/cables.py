import json
import yaml
import logging
import os
import glob
from utilities import devicemanagement as dm
from utilities import helper


def to_sot(result, conn, device_facts, device_defaults, onboarding_config):
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    directory = os.path.join(BASEDIR, '../conf/cables')
    files = []

    for filename in glob.glob(os.path.join(directory, "*.yaml")):
        with open(filename) as f:
            logging.debug("opening file %s to read facts config" % filename)
            try:
                config = yaml.safe_load(f.read())
                if config is None:
                    logging.error("could not parse file %s" % filename)
                    continue
            except Exception as exc:
                logging.error("could not read file %s; got exception %s" % (filename, exc))
                continue

            active = config.get('active')
            name = config.get('name')
            if not active:
                logging.debug("config context %s in %s is not active" % (name, filename))
                continue

            file_vendor = config.get("vendor")
            if file_vendor is None or file_vendor != device_defaults["manufacturer"]:
                logging.debug("skipping file %s (%s)" % (filename, file_vendor))
                continue

            files.append(os.path.basename(filename))
            values = dm.send_and_parse_command(conn,
                                               config['cables'],
                                               device_defaults['platform'])

            # print(json.dumps(values, indent=4))
            first_command = config['cables'][0]['command']['cmd']
            for value in values[first_command]:
                connection = {"side_a": device_facts['fqdn'],
                              "side_b": value['side_b'],
                              "interface_a": value['local'],
                              "interface_b": value['remote'],
                              "cable_type": "cat5e"
                              }
                newconfig = {
                    "name": device_facts['fqdn'],
                    "config": connection
                }
                result['cables']["todo"] = helper.send_request("updateconnection",
                                                              onboarding_config["sot"]["api_endpoint"],
                                                              newconfig)

    result[device_facts["fqdn"]]['cable'] = "Processing cables %s" % files


# def to_sot(result, conn, device_facts, onboarding_config):
#     # get layer2 neighbors
#     response = conn.send_command("show cdp neighbors")
#     r = response.genie_parse_output()
#
#     for line in r['cdp']['index']:
#         device_id = r['cdp']['index'][line]['device_id']
#         local_interface = r['cdp']['index'][line]['local_interface']
#         port_id = r['cdp']['index'][line]['port_id']
#         logging.debug("adding %s %s %s %s" % (device_facts['fqdn'],
#                                               local_interface,
#                                               device_id,
#                                               port_id))
#
#         connection = {
#             "side_a": device_facts['fqdn'],
#             "side_b": device_id,
#             "interface_a": local_interface,
#             "interface_b": port_id,
#             "cable_type": "cat5e"
#         }
#         newconfig = {
#             "name": device_facts['fqdn'],
#             "config": connection
#         }
#         result['cables'][line] = helper.send_request("updateconnection",
#                                                onboarding_config["sot"]["api_endpoint"],
#                                                newconfig)
