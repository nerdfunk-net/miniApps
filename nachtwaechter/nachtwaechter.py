#!/usr/bin/env python

import argparse
import logging
import os
import getpass
import asyncio
import json
import sys
import yaml
import textfsm
import time
import tabulate
from utilities import utilities
from dotenv import load_dotenv, dotenv_values
from scrapli.driver.core import AsyncIOSXEDriver, AsyncIOSXRDriver, AsyncNXOSDriver
from scrapli.logging import enable_basic_logging


BASEDIR = os.path.abspath(os.path.dirname(__file__))
DEFAULT_CONFIG_FILE = "./conf/nachtwaechter.yaml"
TEMPLATES_INDEX = "./conf/index.yaml"
TEMPLATES_DIR = "./conf/textfsm/"
TARGET_DIR = "./facts"
DEFAULT_THREADS = 2
MAX_ATTEMPTS = 3
visited_devices = set()
visited_devices_names = set()
hosts_with_errors = set()
blacklisted_hosts = set()
summary = []
statistics = {}
mappings = {}
enable_basic_logging(file=True, level="INFO")

# temp
COUNTER = 0


def get_username_and_password(args):
    username = None
    password = None

    if args.profile is not None:
        logging.debug("using profile %s" % args.profile)
        profile = args.profile
        account = utilities.get_profile(nachtwaechter_config, profile)
        if not account['success']:
            logging.error("could not retrieve username and password")
        else:
            username = account.get('username')
            password = account.get('password')
    if username is None:
        username = input("Username (%s): " % getpass.getuser())
        if username == "":
            username = getpass.getuser()
    elif args.username is not None:
        username = args.username

    if password is None and args.password is None:
        password = getpass.getpass(prompt="Enter password for %s: " % username)
    else:
        if args.password is not None:
            password = args.password

    logging.debug("username=%s, password=%s" % (username, password))

    return username, password


def write_data_to_disk(host, data, params):

    filename = "%s/%s%s" % (params['target'], host, params['postfix'])
    print ("writing data to %s" % filename)

    if params['format'] == 'json':
        with open(filename, "w") as filehandler:
            filehandler.write(json.dumps(data, indent=4))
            filehandler.close()
    elif params['format'] == 'yaml':
        with open(filename, "w") as filehandler:
            filehandler.write(yaml.dump(data, default_flow_style=False))
            filehandler.close()
    elif params['format'] == "table":
        header = data[0].keys()
        rows = [x.values() for x in data]
        tab = tabulate.tabulate(rows, header)
        with open(filename, "w") as filehandler:
            filehandler.write(tab)
            filehandler.close()


def print_dataset(host, result, params):

    if not params['show_cdp']:
        if 'show cdp neighbors detail' in result:
            del result['show cdp neighbors detail']
        if 'show ip bgp neighbors' in result:
            del result['show ip bgp neighbors']
        result["echo"] = {'host_ip': host, 'echo': True}

    output_format = params.get('format', 'json')
    if output_format == 'json':
        print(json.dumps(result, indent=4))
    elif output_format == "yaml":
        print(yaml.dump(resul))
    elif output_format == "table":
        # if the table was joined it is a list, otherwise a dict
        if isinstance(result, dict):
            try:
                for key, values in result.items():
                        if len(values) > 0:
                            header = values[0].keys()
                            rows = [x.values() for x in values]
                            tab = tabulate.tabulate(rows, header)
                            print(tab)
            except Exception as exc:
                print("got exception; fallback to json (dict)")
                print(json.dumps(result, indent=4))
        else:
            try:
                if len(result) > 0:
                    header = result[0].keys()
                    rows = [x.values() for x in result]
                    tab = tabulate.tabulate(rows, header)
                    print(tab)
            except Exception as exc:
                print("got exception; fallback to json (not dict)")
                print(json.dumps(result, indent=4))


def join_values(origin, name1, name2, key1, key2) -> list:

    target = []
    for l1 in origin[name1]:
        for l2 in origin[name2]:
            v1 = l1.get(key1)
            v2 = l2.get(key2)
            if v1 == v2:
                target.append(l1 | l2)
    return target


def merge_tables(values, template_config, profile) -> list:

    final_set = []
    template = {}

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

    return final_set


async def send_commands(worker, commands, params, host_ip, platform="ios"):

    global visited_devices
    global hosts_with_errors
    global statistics
    global CURRENT_CONNECTIONS

    result = {}
    echo = False

    device = {
        'host': host_ip,
        'auth_username': params["auth_username"],
        'auth_password': params["auth_password"],
        "auth_strict_key": False,
        "transport": "asyncssh",
        "timeout_socket": 10,
        "timeout_transport": 10,
        "timeout_ops": 120,
        "ssh_config_file": "/etc/ssh/ssh_config",
        # "ssh_config_file": True
    }
    if host_ip not in statistics:
        statistics[host_ip] = dict(device)

    if platform == 'nxos':
        driver = AsyncNXOSDriver
    else:
        driver = AsyncIOSXEDriver

    # prepare commands to send to our device
    # remove echo, this is not a valid cisco command
    cmds = []
    for cmd in commands:
        if cmd == "echo":
            echo = True
        else:
            cmds.append(commands[cmd]['command'])

    try:
        print("(%s) connecting to %s (%s)" % (worker, host_ip, platform))
        async with driver(**device) as conn:
            print("(%s) successfully logged in to %s (%s)" % (worker, host_ip, platform))
            if len(cmds) > 0:
                print("(%s) Sending %s commands to %s" % (worker, len(cmds), host_ip))
                responses = await conn.send_commands(cmds)
                print("(%s) successfully sent %s commands to %s" % (worker, len(cmds), host_ip))
            else:
                if echo:
                    print("(%s) log echo for %s" % (worker, host_ip))
                    return True, {'echo': {'host_ip': host_ip, 'echo': True}}
                else:
                    print("(%s) return {} for %s" % (worker, host_ip))
                    return False, {}
    except Exception as exc:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        message = "(%s) error got exception in line %s: %s (%s, %s, %s)" % (worker,
                                                                            exc_tb.tb_lineno,
                                                                            exc, exc_type,
                                                                            exc_obj,
                                                                            exc_tb)
        print(message)
        return False, message

    # now parse the response of the commands
    for response in responses:
        channel_input = response.channel_input
        print("(%s) channel_input: %s" % (worker, channel_input))
        filename = "%s/%s" % (TEMPLATES_DIR, commands[channel_input]['template'][platform])
        try:
            template = open(filename)
            re_table = textfsm.TextFSM(template)
            fsm_results = re_table.ParseText(response.result)
            collection_of_results = [dict(zip(re_table.header, pr)) for pr in fsm_results]
            result[channel_input] = collection_of_results
        except Exception as exc:
            # this is an error while parsing not connecting
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("(%s) parser error in line %s; got: %s (%s, %s, %s)" % (worker,
                                                                          exc_tb.tb_lineno,
                                                                          exc,
                                                                          exc_type,
                                                                          exc_obj,
                                                                          exc_tb))
            result[channel_input] = "Parsing failed"

    return True, result


async def worker(worker, queue, params):

    global visited_devices
    global visited_devices_names
    global hosts_with_errors
    global blacklisted_hosts
    global statistics
    global mappings
    global COUNTER

    while True:
        q = await queue.get()
        if q['host_ip'] not in visited_devices and \
           q['hostname'] not in visited_devices_names:
            print("(%s) polling device: %s" % (worker, q['host_ip']))
            success, result = await send_commands(worker, params['commands'], params, q['host_ip'], q['platform'])
            if not success:
                # increase error counter of device
                if 'errors' in statistics[q['host_ip']]:
                    statistics[q['host_ip']]['errors'] = statistics[q['host_ip']]['errors'] + 1
                else:
                    statistics[q['host_ip']]['errors'] = 1

                if statistics[q['host_ip']]['errors'] < MAX_ATTEMPTS:
                    print("(%s) re-adding %s/%s to queue (cdp)" % (worker, q['host_ip'], q['platform']))
                    queue.put_nowait({'host_ip': q['host_ip'], 'hostname': q['hostname'], 'platform': q['platform']})
                    hosts_with_errors.add(q['host_ip'])
                    summary.append({'host': q['host_ip'],
                                    'hostname': q['hostname'],
                                    'platform': q['platform'],
                                    'polling': 'failure',
                                    'adding': "---"})
                # task is done
                queue.task_done()
                continue

            # successfully logged in, remove from error list if present
            if q['host_ip'] in hosts_with_errors:
                hosts_with_errors.remove(q['host_ip'])

            visited_devices.add(q['host_ip'])
            if q['hostname'] != 'unknown' and q['hostname'] != 'seed':
                visited_devices_names.add(q['hostname'])

            for cmd in result:
                # get neighbors and add them to queue
                hosts = set()
                # check if we have cdp to parse
                if params['walk'] and cmd == "show cdp neighbors detail":
                    for line in result[cmd]:
                        host = line.get('MANAGEMENT_IP')
                        if host is None or host == "":
                            host = line.get('INTERFACE_IP')
                        if host is None or host == "":
                            print("(%s) could either parse MANAGEMENT_IP nor INTERFACE_IP on %s" % (worker, q['host_ip']))
                            break
                        software = line.get('SOFTWARE_VERSION')
                        hostname = line.get('DESTINATION_HOST')
                        # check if mapping exists
                        if host in mappings:
                            host = mappings[host]
                        elif hostname in mappings:
                            host = mappings[hostname]
                        if software is not None and ('NXOS' in software or 'NX-OS' in software):
                            platform = "nxos"
                        elif software is not None and 'IOS' in software:
                            platform = "ios"
                        else:
                            # eg VMWare ESXi (switch)
                            print("unknown neighbor platform - %s/%s - on %s" % (software, host, q['host_ip']))
                            break
                        if host not in hosts and \
                           host not in visited_devices and \
                           hostname not in visited_devices_names and \
                           host not in blacklisted_hosts:
                            # check if we have a maximum number of attempts reached
                            errors = 0
                            if host in statistics:
                                errors = statistics[host].get('errors', 0)
                            if errors < MAX_ATTEMPTS:
                                COUNTER += 1
                                hosts.add(host)
                                print("(%s) adding %s/%s to queue (%s/cdp)" % (worker, host, platform, COUNTER))
                                queue.put_nowait({'host_ip': host, 'hostname': hostname, 'platform': platform})

                if params['walk'] and cmd == "show ip bgp neighbors":
                    for line in result[cmd]:
                        host = line['REMOTE_IP']
                        # check if mapping exists
                        if host in mappings:
                            host = mappings[host]

                        platform = "ios"
                        if host not in hosts and \
                           host not in blacklisted_hosts and \
                           host not in visited_devices and \
                           host != "0.0.0.0":
                            # check if we have a maximum number of attempts reached
                            errors = 0
                            if host in statistics:
                                errors = statistics[host].get('errors', MAX_ATTEMPTS)
                            if errors < MAX_ATTEMPTS:
                                COUNTER += 1
                                hosts.add(host)
                                print("(%s) adding %s/%s to queue (%s/bgp)" % (worker, host, platform, COUNTER))
                                queue.put_nowait({'host_ip': host, 'hostname': 'unknown', 'platform': platform})

                # check if we have show ip route
                if params['walk'] and cmd == "show ip route":
                    for line in result[cmd]:
                        host = line['NEXTHOP_IP']
                        # check if mapping exists
                        if host in mappings:
                            host = mappings[host]

                        platform = "ios"
                        if host not in hosts and \
                           host not in blacklisted_hosts and \
                           host not in visited_devices and \
                           host != "0.0.0.0":
                            # check if we have a maximum number of attempts reached
                            errors = 0
                            if host in statistics:
                                errors = statistics[host].get('errors', MAX_ATTEMPTS)
                            if errors < MAX_ATTEMPTS:
                                COUNTER += 1
                                hosts.add(host)
                                print("(%s) adding %s/%s to queue (%s/route)" % (worker, host, platform, COUNTER))
                                queue.put_nowait({'host_ip': host, 'hostname': 'unknown', 'platform': platform})

            if 'join' in params:
                result = merge_tables(result, params['join']['destination']['value'], params['join'])

            # save summary data
            if len(hosts) == 0:
                h = "---"
            else:
                h = ','.join(hosts)
            summary.append({'host': q['host_ip'],
                            'hostname': q['hostname'],
                            'platform': q['platform'],
                            'polling': 'success',
                            'adding': h})

            if params['write']:
                write_data_to_disk(q['host_ip'], result, params)
            if params['print']:
                print_dataset(q['host_ip'], result, params)

        else:
            print("Skipping %s (%s)" % (q['host_ip'], q['hostname']))
        # Notify the queue that the "work item" has been processed.
        queue.task_done()


async def main(seed, params):
    num_of_nodes = params['threads']
    print("starting %s tasks" % num_of_nodes)

    # Create a queue that we will use to store our "workload".
    queue = asyncio.Queue()
    # put initial seed device in queue
    queue.put_nowait(seed)

    # Create worker tasks to process the queue concurrently.
    tasks = []
    for i in range(num_of_nodes):
        task = asyncio.create_task(worker(i, queue, params))
        tasks.append(task)

    # Wait until the queue is fully processed.
    await queue.join()

    # Cancel our worker tasks.
    for task in tasks:
        task.cancel()

    # Wait until all worker tasks are cancelled.
    await asyncio.gather(*tasks, return_exceptions=True)

    # print statistics
    print("-============ Statistics ============-")
    runtime = time.time() - int(params['started'])
    print("Runtime: %d" % runtime)
    print("Hosts scanned: %s" % len(visited_devices))
    print("hosts with errors: %s" % len(hosts_with_errors))
    for host in hosts_with_errors:
        if host in statistics:
            errors = statistics[host].get('errors')
        print("host: %s errors: %s" % (host, errors))

    header = summary[0].keys()
    rows = [x.values() for x in summary]
    tab = tabulate.tabulate(rows, header)
    print(tab)

if __name__ == "__main__":

    # defaults
    profile = "reachability"
    walk = False
    write = False
    print_output = False
    commands = {}
    params = {}
    postfix = ""
    output_format = ""
    show_cdp = False

    parser = argparse.ArgumentParser()
    # what to do
    parser.add_argument('--seed', type=str, required=False)
    parser.add_argument('--device', type=str, required=False)
    parser.add_argument('--platform', type=str, default='ios')
    # the blacklist contains IP that are not used
    parser.add_argument('--blacklist', type=str, default='')
    parser.add_argument('--mapping', type=str, default='')
    # what todo
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--reachability', action='store_true')
    parser.add_argument('--commands', type=str, required=False)
    # how to walk
    parser.add_argument('--no-walk-cdp', action='store_true')
    parser.add_argument('--walk-route', action='store_true')
    parser.add_argument('--walk-bgp', action='store_true')
    # output
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--print', action='store_true')
    parser.add_argument('--format', type=str, required=False)
    # we need username and password to connect to the device
    # credentials can be configured using a profile
    # have a look at the config file
    parser.add_argument('--username', type=str, required=False)
    parser.add_argument('--password', type=str, required=False)
    parser.add_argument('--profile', type=str, required=False)
    # the user can enter a different config file
    parser.add_argument('--config', type=str, required=False)
    # facts dir to write collected data to
    parser.add_argument('--output', type=str, required=False)

    args = parser.parse_args()

    # check parameter
    if not args.seed and not args.device:
        print("Either seed (scanning) or device must be used")
        sys.exit()
    if args.seed:
        todo = "scan"
        walk = True
        starting_point = args.seed
    elif args.device:
        todo = "device"
        walk = False
        starting_point = args.device

    if args.output is None:
        target_dir = TARGET_DIR
    else:
        target_dir = args.output

    if args.reachability:
        profile = "reachability"

    # Connect the path with the '.env' file name
    load_dotenv(os.path.join(BASEDIR, '.env'))
    # you can get the env variable by using var = os.getenv('varname')

    # read nachtwaechter config
    if args.config is not None:
        config_file = args.config
    else:
        config_file = DEFAULT_CONFIG_FILE
    nachtwaechter_config = utilities.read_config(config_file)

    # set logging
    cfg_loglevel = utilities.get_value_from_dict(nachtwaechter_config, ['nachtwaechter', 'logging', 'level'])
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
    log_format = utilities.get_value_from_dict(nachtwaechter_config, ['nachtwaechter', 'logging', 'format'])
    if log_format is None:
        log_format = '%(asctime)s %(levelname)s:%(message)s'
    logfile = utilities.get_value_from_dict(nachtwaechter_config, ['nachtwaechter', 'logging', 'filename'])
    logging.basicConfig(level=loglevel,
                        format=log_format,
                        filename=logfile)
    logging.debug("config %s read" % config_file)

    # get username and password
    username, password = get_username_and_password(args)

    # set some parameter
    if args.baseline:
        profile = "baseline"
    elif args.reachability:
        profile = "reachability"
    else:
        if not args.commands:
            print("no profile specified")
            sys.exit()
        profile = args.commands

    # read profile and postfix
    if profile not in nachtwaechter_config['profiles']:
        print("Unknown profile %s" % profile)
        sys.exit()

    template_index = utilities.read_config(TEMPLATES_INDEX)['index']
    profile_config = nachtwaechter_config['profiles'][profile]
    postfix = profile_config.get('postfix')
    output_format = profile_config.get('format', 'json')
    # overwrite format if user want a different one
    if args.format:
        output_format = args.format

    if 'join' in profile_config:
        params.update({'join': profile_config['join']})
    for line in profile_config['commands']:
        if line['command'] == "echo":
            commands['echo'] = 'echo'
        else:
            for index in template_index:
                if index['command'] == line['command']:
                    commands[index['command']] = index
                if line['command'] == "show cdp neighbors detail":
                    show_cdp = True

    if walk:
        if not args.no_walk_cdp:
            commands.update ({"show cdp neighbors detail": {
                "command": "show cdp neighbors detail",
                "template": {
                    "ios": "cisco_ios_show_cdp_neighbors_detail.textfsm",
                    "nxos": "cisco_nxos_show_cdp_neighbors_detail.textfsm"
                }
            }})
        if args.walk_route:
            commands.update ({"show ip route": {
                "command": "show ip route",
                "template": {
                    "ios": "cisco_ios_show_ip_route.textfsm",
                    "nxos": "cisco_nxos_show_ip_route.textfsm"
                }
            }})
        if args.walk_bgp:
            commands.update ({"show ip bgp neighbors": {
                "command": "show ip bgp neighbors",
                "template": {
                    "ios": "cisco_ios_show_ip_bgp_neighbors.textfsm",
                    "nxos": "cisco_nxos_show_ip_bgp_neighbors.textfsm"
                }
            }})

    # set number of parallel tasks
    if 'threads' in nachtwaechter_config['nachtwaechter']:
        threads = nachtwaechter_config['nachtwaechter']['threads']
    else:
        threads = DEFAULT_THREADS

    # read blacklist
    if args.blacklist:
        if os.path.isfile(BASEDIR + "/conf/%s" % args.blacklist):
            with open(BASEDIR + "/conf/%s" % args.blacklist, "r") as filehandler:
                hosts = filehandler.read().splitlines()
                for h in hosts:
                    blacklisted_hosts.add(h)
        else:
            print("blacklist %s configured but not found" % (BASEDIR + "/conf/%s" % args.blacklist))

    # read mapping
    if args.mapping:
        if os.path.isfile(BASEDIR + "/conf/%s" % args.mapping):
            with open(BASEDIR + "/conf/%s" % args.mapping, "r") as filehandler:
                mappings_config = utilities.read_config(BASEDIR + "/conf/%s" % args.mapping)
            for mapping in mappings_config['mappings']:
                mappings[mapping['mapping']['src']] = mapping['mapping']['dest']
        else:
            print("mapping configured but not found")

    params.update({
        'started': time.time(),
        'threads': threads,
        'auth_username': username,
        'auth_password': password,
        'target': target_dir,
        'commands': commands,
        'profile': profile,
        'postfix': postfix,
        'todo': todo,
        'walk': walk,
        'write': args.write,
        'print': args.print,
        'format': output_format,
        'show_cdp': show_cdp
    })

    # print(json.dumps(params, indent=4))
    asyncio.run(main({'host_ip': starting_point, 'hostname': 'seed', 'platform': args.platform}, params))
