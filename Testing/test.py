#!/usr/bin/env python

import yaml
import json
import tabulate

values = {}


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
