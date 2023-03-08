#!/usr/bin/env python

import argparse
import logging
import os
import getpass
import json
import asyncio
import time
import sys
import tabulate
from datetime import datetime
from utilities import utilities
from utilities import devicemanagement as dm
from dotenv import load_dotenv, dotenv_values
from scrapli.driver.core import AsyncIOSXEDriver, AsyncIOSXRDriver, AsyncNXOSDriver
from scrapli.logging import enable_basic_logging


BASEDIR = os.path.abspath(os.path.dirname(__file__))
DEFAULT_CONFIG_FILE = "./conf/backup.yaml"
DEFAULT_THREADS = 2
BACKUP_DIR = "./backups"
summary = []

"""
Filter:
   - name=devicename
     role=rolename
     model=device type slug
"""


def get_username_and_password(args):
    username = None
    password = None

    if args.profile is not None:
        logging.debug("using profile %s" % args.profile)
        profile = args.profile
        account = utilities.get_profile(backup_config, profile)
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


def write_config_to_disk(host, command, config, params):

    if command == "show startup-config":
        config_type = "startup"
    else:
        config_type = "running"

    filename = "%s/%s/%s.%s%s" % (BASEDIR, params['target'], host, config_type, params['postfix'])
    print("writing data to %s" % filename)
    try:
        with open(filename, "w") as filehandler:
            filehandler.write(config)
            filehandler.close()
        return True
    except Exception as exc:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        message = "(%s) error got exception in line %s: %s (%s, %s, %s)" % (worker,
                                                                            exc_tb.tb_lineno,
                                                                            exc, exc_type,
                                                                            exc_obj,
                                                                            exc_tb)
        print(message)
        return false


async def get_configs(worker, params, host_ip, hostname, platform="ios"):

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

    if platform == 'nxos':
        driver = AsyncNXOSDriver
    else:
        driver = AsyncIOSXEDriver

    cmds = []
    if params['running_config']:
        cmds.append('show running-config')
    if params['startup_config']:
        cmds.append('show startup-config')

    try:
        print("(%s) connecting to %s (%s)" % (worker, host_ip, platform))
        async with driver(**device) as conn:
            print("(%s) successfully logged in to %s (%s)" % (worker, host_ip, platform))
            responses = await conn.send_commands(cmds)
            print("(%s) successfully sent command to %s" % (worker, host_ip))
    except Exception as exc:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        message = "(%s) error got exception in line %s: %s (%s, %s, %s)" % (worker,
                                                                            exc_tb.tb_lineno,
                                                                            exc, exc_type,
                                                                            exc_obj,
                                                                            exc_tb)
        return False, message

    return True, responses


async def worker(worker, queue, params):

    while True:
        q = await queue.get()
        summary_data = {'host': q['host_ip'],
                        'hostname': q['hostname'],
                        'platform': q['platform']}
        print("(%s) Processing %s/%s" % (worker, q['host_ip'], q['platform']))
        success, responses = await get_configs(worker, params, q['host_ip'], q['hostname'], q['platform'])
        if not success:
            if params['running_config']:
                summary_data['show running-config'] = False
            if params['startup_config']:
                summary_data['show startup-config'] = False
            summary.append(summary_data)
        else:
            for response in responses:
                result = write_config_to_disk(q['hostname'], response.channel_input, response.result, params)
                summary_data[response.channel_input] = result
            summary.append(summary_data)
        # task is done
        queue.task_done()


async def main(device_list, params):
    num_of_nodes = params['threads']
    print("starting %s tasks" % num_of_nodes)

    # Create a queue that we will use to store our "workload".
    queue = asyncio.Queue()
    # put device list in queue
    for device in device_list:
        queue.put_nowait(device)

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
    print("Hosts processed: %s" % len(summary))
    header = summary[0].keys()
    rows = [x.values() for x in summary]
    tab = tabulate.tabulate(rows, header)
    print(tab)


if __name__ == "__main__":

    # defaults
    params = {}
    device_list = []

    parser = argparse.ArgumentParser()
    # what to do
    parser.add_argument('--no-running-config', action='store_false')
    parser.add_argument('--startup-config', action='store_true')
    #
    # which devices to backup
    parser.add_argument('--devices', type=str, required=True)
    # where to save
    parser.add_argument('--directory', type=str, required=False)
    parser.add_argument('--repo', type=str, required=False)
    parser.add_argument('--postfix', type=str, required=False)
    # the user can enter a different config file
    parser.add_argument('--config', type=str, required=False)
    # we need username and password to connect to the device
    # credentials can be configured using a profile
    # have a look at the config file
    parser.add_argument('--username', type=str, required=False)
    parser.add_argument('--password', type=str, required=False)
    parser.add_argument('--profile', type=str, required=False)

    args = parser.parse_args()

    # Connect the path with the '.env' file name
    load_dotenv(os.path.join(BASEDIR, '.env'))
    # you can get the env variable by using var = os.getenv('varname')

    # read backup config
    if args.config is not None:
        config_file = args.config
    else:
        config_file = DEFAULT_CONFIG_FILE
    backup_config = utilities.read_config(config_file)

    # set logging
    cfg_loglevel = utilities.get_value_from_dict(backup_config, ['backup', 'logging', 'level'])
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
    log_format = utilities.get_value_from_dict(backup_config, ['backup', 'logging', 'format'])
    if log_format is None:
        log_format = '%(asctime)s %(levelname)s:%(message)s'
    logfile = utilities.get_value_from_dict(backup_config, ['backup', 'logging', 'filename'])
    logging.basicConfig(level=loglevel,
                        format=log_format,
                        filename=logfile)
    logging.debug("config %s read" % config_file)

    # get username and password
    username, password = get_username_and_password(args)

    if args.devices is not None:
        devices = dm.get_devices(backup_config["sot"]["api_endpoint"], args.devices)
        for device in devices["result"]:
            device_list.append({'host_ip': device["primary_ip4"],
                                'hostname': device["hostname"],
                                'platform': device["platform"]["slug"]})

    # print(json.dumps(device_list, indent=4))

    # set number of parallel tasks
    if 'threads' in backup_config['backup']:
        threads = backup_config['backup']['threads']
    else:
        threads = DEFAULT_THREADS

    if args.directory is None:
        target = BACKUP_DIR
    else:
        target = args.directory

    if args.postfix is None:
        now = datetime.now()
        postfix = ".%s" % now.strftime("%Y%m%d")
    else:
        postfix = args.postfix

    if not args.no_running_config and not args.startup_config:
        print("Either running or startup config must be used")
        sys.exit()

    params.update({
        'started': time.time(),
        'threads': threads,
        'auth_username': username,
        'auth_password': password,
        'target': target,
        'postfix': postfix,
        'running_config': args.no_running_config,
        'startup_config': args.startup_config
    })

    # print(params)
    asyncio.run(main(device_list, params))