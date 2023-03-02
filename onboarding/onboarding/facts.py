import json
import logging
import os
import glob
import yaml
import textfsm
import sys
from utilities import devicemanagement as dm


def process_facts(conn, config, platform):
    facts = {}
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    directory = os.path.join(BASEDIR, '../conf/textfsm')

    for fact in config['facts']:
        command = fact["command"]["cmd"]
        logging.debug("sending command %s" % command)
        response = conn.send_command(command)

        filename = fact["command"]["template"].get(platform)
        if filename is None:
            logging.error("no template for platform %s configutred" % platform)
            return facts

        if not os.path.isfile("%s/%s" % (directory, filename)):
            logging.error("template %s does not exists" % filename)
            return facts

        try:
            template = open("%s/%s" % (directory, filename))
            re_table = textfsm.TextFSM(template)
            fsm_results = re_table.ParseText(response.result)
            collection_of_results = [dict(zip(re_table.header, pr)) for pr in fsm_results]
            facts[command] = collection_of_results
        except Exception as exc:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("parser error in line %s; got: %s (%s, %s, %s)" % (exc_tb.tb_lineno,
                                                                     exc,
                                                                     exc_type,
                                                                     exc_obj,
                                                                     exc_tb))
    return facts


def get_facts(conn, result, device_defaults):
    """

    :param conn:
    :param result
    :param device_defaults:
    :return:
    """
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    directory = os.path.join(BASEDIR, '../conf/facts')
    files = []
    my_list = []
    facts = {}
    parentheses = r"{{.*}}"

    # read all facts from config
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
            values = dm.send_and_parse_command(conn, config['facts'], device_defaults['platform'])
            # print(json.dumps(values, indent=4))

    facts["manufacturer"] = device_defaults["manufacturer"]
    if "show version" in values:
        facts["os_version"] = values["show version"][0]["VERSION"]
        facts["software_image"] = values["show version"][0]["SOFTWARE_IMAGE"]
        facts["serial_number"] = values["show version"][0]["SERIAL"]
        facts["model"] = values["show version"][0]["HARDWARE"][0]
        facts["hostname"] = values["show version"][0]["HOSTNAME"]

    if "show hosts summary" in values:
        facts["fqdn"] = "%s.%s" % (facts["hostname"], values["show hosts summary"][0]["DEFAULT_DOMAIN"])
    else:
        facts["fqdn"] = facts["hostname"]

    logging.debug("processed %s to get facts of device" % files)
    #print(json.dumps(facts, indent=4))

    result[facts["fqdn"]]['facts'] = "Processing facts %s" % files

    return facts

