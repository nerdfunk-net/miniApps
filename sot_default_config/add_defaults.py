#!/usr/bin/env python

import argparse
import json
import yaml
import sys
from helper import helper

# set default config file to your needs
default_config_file = "./config.yaml"


def get_defaults(repo, filename, update=False):
    """
    get default values from sot

    Args:
        repo:
        filename:
        update:

    Returns:

    """

    defaults_str = helper.get_file(config["sot"]["api_endpoint"],
                                   repo,
                                   filename,
                                   update)

    if defaults_str is None:
        print("%s %s does not exists or could not be read" % (repo, filename))
        return None

    # convert defaults to dict
    try:
        data = yaml.safe_load(defaults_str)
    except Exception as exc:
        print("got exception: %s" % exc)
        return None

    return data


def origin_git(config, update=False):
    """

    Args:
        config:
        update:

    Returns:

    """

    # we use a dict to store our results
    result = {}

    repo = config['files']['sites']['repo']
    prefix_filename = config['files']['prefixe']['filename']
    defaults_filename = config['files']['defaults']['filename']
    sites_filename = config['files']['sites']['filename']
    tags_filename = config['files']['tags']['filename']

    # get default values from repo
    prefixe = get_defaults(repo, prefix_filename,update)
    if prefixe is None:
        print("could not read default values from %s/%s" % (repo, prefix_filename))
        return None

    defaults = get_defaults(repo, defaults_filename,update)
    if defaults is None:
        print("could not read default values from %s/%s" % (repo, defaults_filename))
        return None

    sites = get_defaults(repo, sites_filename,update)
    if sites is None:
        print("could not read default values from %s/%s" % (repo, sites_filename))
        return None

    # now add sites first
    for site in sites['sites']:
        site_config = {
            "slug": site['slug'],
            "config": site
        }
        result['sites'] = helper.send_request('site',
                                              config["sot"]["api_endpoint"],
                                              site_config)

    # add manufacturers
    for m in defaults['manufacturers']:
        manufacturers_config = {
            "slug": m['slug'],
            "config": m
        }
        result['manufacturers'] = helper.send_request('manufacturer',
                                                      config["sot"]["api_endpoint"],
                                                      manufacturers_config)

    # add platform
    for p in defaults['platforms']:
        platform_config = {
            "slug": p['slug'],
            "config": p
        }
        result['platform'] = helper.send_request('platform',
                                                 config["sot"]["api_endpoint"],
                                                 platform_config)

    # add device role
    for r in defaults['device_roles']:
        role_config = {
            "slug": r['slug'],
            "config": r
        }
        result['role'] = helper.send_request('devicerole',
                                             config["sot"]["api_endpoint"],
                                             role_config)

    # add device types
    for d in defaults['devicetype']:
        devicetype_config = {
            "slug": d['slug'],
            "config": d
        }
        result['platform'] = helper.send_request('devicetype',
                                                 config["sot"]["api_endpoint"],
                                                 devicetype_config)

    # add prefixe
    result['prefixe'] = {}
    for p in prefixe['prefixe']:
        prefix_config = {'prefix': p}
        # status is mandatory
        if 'status' in prefixe['prefixe'][p]:
            prefix_config['status'] = prefixe['prefixe'][p]['status']
        else:
            prefix_config['status'] = "active"
        # all other parameters are optional
        if 'site' in prefixe['prefixe'][p]:
            prefix_config['site'] = prefixe['prefixe'][p]['site']
        data = {
            "prefix": p,
            "config": prefix_config
        }
        result['prefixe'][p] = helper.send_request('prefix',
                                                   config["sot"]["api_endpoint"],
                                                   data)

    # adding tags to our SOT is optional
    tags = get_defaults(repo, tags_filename, update)
    if tags is None:
        print("could not read tags from %s/%s" % (repo, tags_filename))
    else:
        result['device_tags'] = {}
        for t in tags['tags']:
            data = {'name': t['name'],
                    'description': t['description'],
                    'slug': t['slug'],
                    'content_types': t['content_types']
                    }
            result['device_tags'][t['name']] = helper.send_request('publish_tag_to_sot',
                                                                   config["sot"]["api_endpoint"],
                                                                   data)

    print(json.dumps(result, indent=4))


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--origin', type=str, required=True)
    parser.add_argument('--config', type=str, required=False)
    parser.add_argument('--repo', type=str, required=False)
    parser.add_argument('--filename', type=str, required=False)
    parser.add_argument('--update', type=bool, required=False, default=False)

    args = parser.parse_args()

    # read config
    if args.config is not None:
        config_file = args.config
    else:
        config_file = default_config_file
    config = helper.read_config(config_file)

    if args.repo:
        config['files']['sites']['repo'] = args.repo
    if args.filename:
        config['files']['sites']['filename'] = args.filename

    if args.origin == 'git':
        origin_git(config, args.update)
