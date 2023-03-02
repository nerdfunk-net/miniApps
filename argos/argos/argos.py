import os
import textfsm
import re
import yaml
import json
from scrapli import Scrapli
from tabulate import tabulate


class Argos:

    __username = ""
    __password = ""
    __platform = "ios"
    __host = ""
    __basepath = ""
    __templates = ""
    __device = {}
    __conn = None
    __cli_table = None
    __index = {}

    __mapping = {'ios': 'cisco_iosxe',
                 'iosxr': 'cisco_iosxr',
                 'nxos': 'cisco_nxos'
                 }

    def __init__(self, username, password):
        self.__username = username
        self.__password = password
        self.__basepath = os.path.abspath(os.path.dirname(__file__))
        self.__templates = "%s/../conf/textfsm/" % self.__basepath
        self.__index_file = "%s/../conf/index.yaml" % self.__basepath
        self.load_index()

    def set_username(self, username):
        self.__username = username

    def set_password(self, password):
        self.__password = password

    def set_platform(self, platform):
        self.__platform = self.__mapping[platform]

    def load_index(self):
        with open(self.__index_file) as f:
            self.__index = yaml.safe_load(f.read())

    def get_index(self, cli):
        for item in self.__index['index']:
            if re.search(item['pattern'], cli):
                return item

        return None

    def open(self, host):

        device = {
            "host": host,
            "auth_username": self.__username,
            "auth_password": self.__password,
            "auth_strict_key": False,
            "platform": self.__mapping[self.__platform],
            "ssh_config_file": "~/.ssh/ssh_config"
        }
        self.__conn = Scrapli(**device)
        self.__conn.open()

    def close(self):
        if self.__conn is not None:
            self.__conn.close()

    def show(self, command):

        tpl = self.get_index(command)
        if tpl is None:
            return

        try:
            filename = "%s/%s" % (self.__templates, tpl['template'][self.__platform])
            template = open(filename)
        except Exception as exc:
            print("exception: %s" % exc)

        try:
            response = self.__conn.send_command(tpl['command'])
            re_table = textfsm.TextFSM(template)
            fsm_results = re_table.ParseText(response.result)
            collection_of_results = [dict(zip(re_table.header, pr)) for pr in fsm_results]
            output = tpl.get('output')
            if output == "table":
                print(tabulate(fsm_results, headers=re_table.header))
            elif output == "yaml":
                print(yaml.dump(collection_of_results))
            else:
                print(json.dumps(collection_of_results, indent=2))
        except Exception as exc:
            print("exception: %s" % exc)

