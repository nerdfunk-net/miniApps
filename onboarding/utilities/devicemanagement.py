import json

from scrapli import Scrapli
import logging
import os
import textfsm

def open_connection(host, username, password, platform, port=22):

    """
        open connection the a device

    Args:
        host:
        username:
        password:
        platform:

    Returns:

    """

    # we have to map the napalm driver to our srapli driver / platform
    #
    # napalm | scrapli
    # -------|------------
    # ios    | cisco_iosxe
    # iosxr  | cisco_iosxr
    # nxos   | cisco_nxos

    mapping = {'ios': 'cisco_iosxe',
               'iosxr': 'cisco_iosxr',
               'nxos': 'cisco_nxos'
               }
    driver = mapping.get(platform)
    if driver is None:
        return None

    device = {
        "host": host,
        "auth_username": username,
        "auth_password": password,
        "auth_strict_key": False,
        "platform": driver,
        "port": port,
        "ssh_config_file": "~/.ssh/ssh_config"
    }

    conn = Scrapli(**device)
    conn.open()

    return conn


def get_config(conn, configtype: str) -> str:
    """
    return config from device

    Args:
        conn:
        configtype:

    Returns:
        config: str
    """

    response = conn.send_command("show %s" % configtype)
    return response.result


def send_and_parse_command(conn, commands, platform):
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    directory = os.path.join(BASEDIR, '../conf/textfsm')
    result = {}
    mapped = {}

    for cmd in commands:
        command = cmd["command"]["cmd"]
        logging.debug("sending command %s" % command)
        response = conn.send_command(command)

        filename = cmd["command"]["template"].get(platform)
        if filename is None:
            logging.error("no template for platform %s configutred" % platform)
            result[command] = {}

        if not os.path.isfile("%s/%s" % (directory, filename)):
            logging.error("template %s does not exists" % filename)
            result[command] = {}

        try:
            template = open("%s/%s" % (directory, filename))
            re_table = textfsm.TextFSM(template)
            fsm_results = re_table.ParseText(response.result)
            collection_of_results = [dict(zip(re_table.header, pr)) for pr in fsm_results]
            result[command] = collection_of_results
        except Exception as exc:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("parser error in line %s; got: %s (%s, %s, %s)" % (exc_tb.tb_lineno,
                                                                     exc,
                                                                     exc_type,
                                                                     exc_obj,
                                                                     exc_tb))
            result[command] = {}

        # check if we have a mapping
        # print(json.dumps(result, indent=4))
        if 'mapping' in cmd["command"]:
            if command not in mapped:
                mapped[command] = []
            for res in result[command]:
                m = {}
                for key, value in res.items():
                    is_mapped = False
                    for map in cmd["command"]['mapping']:
                        if key == map["src"]:
                            m[map["dst"]] = value
                            is_mapped = True
                    if not is_mapped:
                        m[key] = value
                mapped[command].append(m)
            result = mapped

    return result