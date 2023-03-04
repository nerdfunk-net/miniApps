import requests
import json
from scrapli import Scrapli


def open_connection(host, username, password, platform, port=22):

    """
        open connection to a device

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


def get_devices(api_endpoint, filter=""):
    #
    # please note: check config.yaml and check if a // is not part of the URL!
    #
    url_request = "%s/get/device/ip/%s" % (api_endpoint, filter)
    print(url_request)
    r = requests.get(url=url_request)

    if r.status_code != 200:
        return {'success': False, 'logs': 'got status code %i' % r.status_code}
    else:
        # we got a json. parse it and check if we have a success or not
        response = json.loads(r.content)

    return response