#!/usr/bin/env python

import yaml
import json
import tabulate

values = {
    "show mac address-table": [
        {
            "DESTINATION_ADDRESS": "0100.0ccc.cccc",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0100.0ccc.cccd",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.0000",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.0001",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.0002",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.0003",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.0004",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.0005",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.0006",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.0007",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.0008",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.0009",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.000a",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.000b",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.000c",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.000d",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.000e",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.000f",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.0010",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0180.c200.0021",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "ffff.ffff.ffff",
            "TYPE": "STATIC",
            "VLAN": "All",
            "DESTINATION_PORT": [
                "CPU"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0021.b73d.661a",
            "TYPE": "DYNAMIC",
            "VLAN": "100",
            "DESTINATION_PORT": [
                "Gi2/0/46"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0021.b73d.a684",
            "TYPE": "DYNAMIC",
            "VLAN": "100",
            "DESTINATION_PORT": [
                "Gi2/0/45"
            ]
        },
        {
            "DESTINATION_ADDRESS": "0800.275f.627f",
            "TYPE": "DYNAMIC",
            "VLAN": "100",
            "DESTINATION_PORT": [
                "Gi1/0/40"
            ]
        },
        {
            "DESTINATION_ADDRESS": "4c52.620f.4494",
            "TYPE": "DYNAMIC",
            "VLAN": "100",
            "DESTINATION_PORT": [
                "Gi1/0/22"
            ]
        },
        {
            "DESTINATION_ADDRESS": "580a.2007.1f51",
            "TYPE": "STATIC",
            "VLAN": "100",
            "DESTINATION_PORT": [
                "Vl100"
            ]
        },
        {
            "DESTINATION_ADDRESS": "6884.7e74.4c91",
            "TYPE": "DYNAMIC",
            "VLAN": "100",
            "DESTINATION_PORT": [
                "Gi1/0/29"
            ]
        },
        {
            "DESTINATION_ADDRESS": "901b.0ec0.1212",
            "TYPE": "DYNAMIC",
            "VLAN": "100",
            "DESTINATION_PORT": [
                "Gi1/0/6"
            ]
        },
        {
            "DESTINATION_ADDRESS": "901b.0ec0.146e",
            "TYPE": "DYNAMIC",
            "VLAN": "100",
            "DESTINATION_PORT": [
                "Gi1/0/7"
            ]
        },
        {
            "DESTINATION_ADDRESS": "901b.0ec0.14bc",
            "TYPE": "DYNAMIC",
            "VLAN": "100",
            "DESTINATION_PORT": [
                "Gi1/0/9"
            ]
        },
        {
            "DESTINATION_ADDRESS": "901b.0ec1.615a",
            "TYPE": "DYNAMIC",
            "VLAN": "100",
            "DESTINATION_PORT": [
                "Gi1/0/40"
            ]
        },
        {
            "DESTINATION_ADDRESS": "901b.0ec7.e8aa",
            "TYPE": "DYNAMIC",
            "VLAN": "100",
            "DESTINATION_PORT": [
                "Gi1/0/32"
            ]
        },
        {
            "DESTINATION_ADDRESS": "901b.0ec8.993f",
            "TYPE": "DYNAMIC",
            "VLAN": "100",
            "DESTINATION_PORT": [
                "Gi1/0/31"
            ]
        },
        {
            "DESTINATION_ADDRESS": "901b.0ec9.2d47",
            "TYPE": "DYNAMIC",
            "VLAN": "100",
            "DESTINATION_PORT": [
                "Gi1/0/18"
            ]
        }
    ],
    "show ip arp": [
        {
            "PROTOCOL": "Internet",
            "ADDRESS": "10.137.1.1",
            "AGE": "-",
            "MAC": "580a.2007.1f51",
            "TYPE": "ARPA",
            "INTERFACE": "Vlan100"
        },
        {
            "PROTOCOL": "Internet",
            "ADDRESS": "10.137.1.50",
            "AGE": "167",
            "MAC": "901b.0ec0.1212",
            "TYPE": "ARPA",
            "INTERFACE": "Vlan100"
        },
        {
            "PROTOCOL": "Internet",
            "ADDRESS": "10.137.1.51",
            "AGE": "40",
            "MAC": "901b.0ec8.993f",
            "TYPE": "ARPA",
            "INTERFACE": "Vlan100"
        },
        {
            "PROTOCOL": "Internet",
            "ADDRESS": "10.137.1.56",
            "AGE": "201",
            "MAC": "901b.0ec7.e8aa",
            "TYPE": "ARPA",
            "INTERFACE": "Vlan100"
        },
        {
            "PROTOCOL": "Internet",
            "ADDRESS": "10.137.1.63",
            "AGE": "199",
            "MAC": "4c52.620f.4494",
            "TYPE": "ARPA",
            "INTERFACE": "Vlan100"
        },
        {
            "PROTOCOL": "Internet",
            "ADDRESS": "10.137.1.73",
            "AGE": "199",
            "MAC": "901b.0ec0.14bc",
            "TYPE": "ARPA",
            "INTERFACE": "Vlan100"
        },
        {
            "PROTOCOL": "Internet",
            "ADDRESS": "10.137.1.80",
            "AGE": "51",
            "MAC": "4c52.620f.4463",
            "TYPE": "ARPA",
            "INTERFACE": "Vlan100"
        },
        {
            "PROTOCOL": "Internet",
            "ADDRESS": "10.137.1.85",
            "AGE": "1",
            "MAC": "901b.0ec0.146e",
            "TYPE": "ARPA",
            "INTERFACE": "Vlan100"
        },
        {
            "PROTOCOL": "Internet",
            "ADDRESS": "10.137.1.86",
            "AGE": "3",
            "MAC": "901b.0ec1.615a",
            "TYPE": "ARPA",
            "INTERFACE": "Vlan100"
        },
        {
            "PROTOCOL": "Internet",
            "ADDRESS": "10.137.1.87",
            "AGE": "204",
            "MAC": "6884.7e74.4c91",
            "TYPE": "ARPA",
            "INTERFACE": "Vlan100"
        },
        {
            "PROTOCOL": "Internet",
            "ADDRESS": "10.137.1.88",
            "AGE": "3",
            "MAC": "0800.275f.627f",
            "TYPE": "ARPA",
            "INTERFACE": "Vlan100"
        },
        {
            "PROTOCOL": "Internet",
            "ADDRESS": "10.137.1.89",
            "AGE": "114",
            "MAC": "901b.0ec9.2d47",
            "TYPE": "ARPA",
            "INTERFACE": "Vlan100"
        },
        {
            "PROTOCOL": "Internet",
            "ADDRESS": "10.137.1.92",
            "AGE": "193",
            "MAC": "901b.0ec0.11d8",
            "TYPE": "ARPA",
            "INTERFACE": "Vlan100"
        },
        {
            "PROTOCOL": "Internet",
            "ADDRESS": "10.137.1.201",
            "AGE": "0",
            "MAC": "0021.b73d.a684",
            "TYPE": "ARPA",
            "INTERFACE": "Vlan100"
        },
        {
            "PROTOCOL": "Internet",
            "ADDRESS": "10.137.1.202",
            "AGE": "3",
            "MAC": "0021.b73d.661a",
            "TYPE": "ARPA",
            "INTERFACE": "Vlan100"
        },
        {
            "PROTOCOL": "Internet",
            "ADDRESS": "10.137.252.1",
            "AGE": "83",
            "MAC": "d824.bd91.2f40",
            "TYPE": "ARPA",
            "INTERFACE": "Port-channel64"
        },
        {
            "PROTOCOL": "Internet",
            "ADDRESS": "10.137.252.2",
            "AGE": "-",
            "MAC": "580a.2007.1f66",
            "TYPE": "ARPA",
            "INTERFACE": "Port-channel64"
        }
    ]
}


def join_values(origin, name1, name2, key1, key2) -> list:

    target = []
    for l1 in origin[name1]:
        for l2 in origin[name2]:
            v1 = l1.get(key1)
            v2 = l2.get(key2)
            if v1 == v2:
                target.append(l1 | l2)
    return target


def main():

    template = {}
    final_set = []
    with open("nachtwaechter.yaml") as f:
        nachtwaechter_config = yaml.safe_load(f.read())

    profile = nachtwaechter_config['profiles']['mac_and_ip']['join']
    template_config = profile['target']['value']

    for t in template_config:
        template[t['key']] = t['value']

    table1 = profile['source'][0]['table']
    table2 = profile['source'][1]['table']
    key1 = profile['source'][0]['key']
    key2 = profile['source'][1]['key']

    dataset = join_values(values, table1, table2, key1, key2)

    for v in dataset:
        t = {}
        for key, value in template.items():
            t[key] = v.get(value)
        final_set.append(t)

    # print(json.dumps(target, indent=4))
    header = final_set[0].keys()
    rows = [x.values() for x in final_set]
    tab = tabulate.tabulate(rows, header)
    print(tab)


if __name__ == "__main__":
    main()
