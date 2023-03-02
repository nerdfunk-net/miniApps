import yaml
import logging
import requests
import json
import os
import glob
import jinja2
import re
from collections import defaultdict
from utilities import helper
from businesslogic import your_config_context as user_cc


# this defaultdict enables us to use infinite numbers of arguments
def inf_defaultdict():
    return defaultdict(inf_defaultdict)


def to_sot(result, device_fqdn, ciscoconf, raw_device_config, device_defaults, onboarding_config):

    device_context = inf_defaultdict()

    # get high level data model of the device
    # the hldm contains the config context
    url_request = "%s/get/hldm/%s/" % (onboarding_config["sot"]["api_endpoint"], device_fqdn)
    r = requests.get(url=url_request)

    if r.status_code != 200:
        logging.error("could not read hldm of %s" % device_fqdn)
        return

    try:
        response = json.loads(r.content)
        sot_device_context = response['data']['device']['config_context']
    except Exception as exc:
        logging.error("could not convert hldm response to json. Got exception %s" % exc)
        return

    standard_config_context(result,
                            device_fqdn,
                            device_context,
                            sot_device_context,
                            ciscoconf,
                            device_defaults,
                            onboarding_config)

    # call the user defined business logic
    # the user defined bl can overwrite and modify the device_context
    user_cc.config_context(result,
                           device_fqdn,
                           device_context,
                           sot_device_context,
                           raw_device_config,
                           onboarding_config)

    print(json.dumps(device_context, indent=4))
    # because our device_context is NOT a dict but a default_dict of default_dicts
    # we have to convert our context to a string, then json and then yaml
    # complicated, maybe there is a better way but it works
    device_context_string = json.dumps(device_context[device_fqdn])
    device_context_json = json.loads(device_context_string)
    device_context_yaml = yaml.dump(device_context_json,
                                    allow_unicode=True,
                                    default_flow_style=False)

    config = {
        'repo': 'config_contexts',
        'filename': "%s.yml" % device_fqdn,
        'subdir': "devices",
        'content': "%s\n%s" % ("---", device_context_yaml),
        'action': 'overwrite',
        'pull': False,
    }

    newconfig = {
        "config": config
    }

    logging.debug("writing config_context to sot")
    response = helper.send_request("editfile",
                                   onboarding_config["sot"]["api_endpoint"],
                                   newconfig)


def standard_config_context(result, device_fqdn, device_context, sot_device_context, ciscoconf, device_defaults, onboarding_config):
    """
    create standard config context and write it to our sot (git)
    Args:
        result:
        device_fqdn:
        device_context:
        sot_device_context:
        ciscoconf:
        device_defaults:
        onboarding_config:

    Returns:

    """

    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    directory = os.path.join(BASEDIR, '../conf/config_context')
    files = []

    # we read all *.yaml files in our config_context config dir
    for filename in glob.glob(os.path.join(directory, "*.yaml")):
        with open(filename) as f:
            logging.debug("opening file %s to read config_context config" % filename)
            try:
                config = yaml.safe_load(f.read())
                if config is None:
                    logging.error("could not parse file %s" % filename)
                    continue
            except Exception as exc:
                logging.error("could not read file %s; got exception %s" % (filename, exc))
                continue

            name = config.get('name')
            platform = config.get('platform')
            if not config.get('active'):
                logging.debug("config context %s in %s is not active" % (name, filename))
                continue
            if platform is not None:
                if platform != 'all' and platform != device_defaults["platform"]:
                    print("skipping config context %s wrong platform %s" % (name, platform))
                    continue

            logging.debug("config context %s in %s is active" % (name, filename))
            # add filename to our list of files that were processed
            files.append(os.path.basename(filename))

            # get the source. It is either a section or a (named) regular expression
            if 'section' in config['source']:
                device_config = ciscoconf.get_section(config['source']['section'])
            elif 'regex' in config['source']:
                device_config = ciscoconf.get_section_by_regular_expression(config['source']['regex'])
            elif 'object' in config['source']:
                if 'name_pattern' in config['source']:
                    device_config = ciscoconf.get_section_as_dict_by_object(config['source']['object'],
                                                                            config['source']['name_pattern'],
                                                                            config['source']['name_group'])
                else:
                    device_config = ciscoconf.get_section_by_object(config['source']['object'])
            elif 'fullconfig' in config['source']:
                device_config = ciscoconf.get_raw_config()
            else:
                logging.error("unknown source %s" % config['source'])
                continue

            if len(device_config) == 0:
                logging.error("no device config with configured pattern found")
                continue

            transform_cleared_config = False
            cleared_config = None
            cleared_config_parsed = None
            if 'grouping' in config['source']:
                group_pattern = config['source']['grouping'].get('group_by_pattern', "")
                group_by = config['source']['grouping'].get('group_by', "")
                remove_from_config = config['source']['grouping'].get('remove_from_config', True)
                transform_cleared_config = config['source']['grouping'].get('transform_cleared_config', False)
                grouped_config, cleared_config = group_device_config(device_config,
                                                                     config,
                                                                     group_pattern,
                                                                     group_by,
                                                                     remove_from_config)

                device_config = grouped_config
                cleared_config_parsed = parse_config(cleared_config, config)

            # print("--- device config ---")
            # print(json.dumps(device_config, indent=4))
            data = parse_config(device_config, config)
            # print("--- data ---")
            # print(json.dumps(data, indent=4))

            final_data = {}
            transformed_data = []
            if 'transform' in config:
                for d in data:
                    transformed_data.append(transform_data(d, config))
                if 'grouping' in config['source']:
                    final_data[config['source']['grouping']['name']] = transformed_data
                else:
                    final_data = transformed_data
            else:
                final_data = data

            if cleared_config_parsed is not None:
                if transform_cleared_config:
                    final_data['cleared'] = transform_data(cleared_config_parsed, config)
                else:
                    final_data['cleared'] = cleared_config_parsed

            #print("--- final data after transformation ---")
            #print(json.dumps(final_data, indent=4))

            # now render data and convert it to json
            if final_data is not None:
                logging.debug("render template if file %s" % filename)
                rendered_data = render_template(final_data, config)
                # print("--- rendered data ---")
                # print(rendered_data)
                try:
                    json_data = json.loads(rendered_data)
                    device_context[device_fqdn][name] = json_data
                    logging.debug("added %s to the device config_context" % name)
                except Exception as exc:
                    logging.error("could not convert template to json data. Got %s" % exc)

    result[device_fqdn]['config_context'] = "Processing config_context %s" % files


def parse_config(device_config, config):

    response = []
    is_list = False
    list_of_list = False

    # check if we have a list of strings or a list of other lists
    # the device_config is always a list
    for block in device_config:
        if isinstance(block, list):
            is_list = True

    # either we have a unnamed block of the config or we have a list of dicts
    # the key of the dict is the name of the matched pattern eg. the interface name
    if not is_list:
        # TODO dokumentieren, wann dieser Fall auftritt. Ist mir auch nicht ganz klar
        if isinstance(device_config[0], str):
            dc = [device_config]
            list_of_list = True
        elif isinstance(device_config[0], dict):
            # we have a "named" dict like a list of the interfaces
            for dc_dict in device_config:
                for key, value in dc_dict.items():
                    data = helper.get_values_from_config_block(value,
                                                               config['patterns'],
                                                               config['named_groups'],
                                                               key)
                    if data is not None:
                        response.append(data)
    else:
        list_of_list = True
        dc = device_config

    if list_of_list:
        for block in dc:
            data = helper.get_values_from_config_block(block, config['patterns'], config['named_groups'])
            if data is not None:
                response.append(data)

    return response


def render_template(config_values, config):

    # print("--- values ---")
    # print(json.dumps({'values': config_values}, indent=4))
    j2 = jinja2.Environment(loader=jinja2.BaseLoader,
                            trim_blocks=False).from_string(config['template'])
    try:
        return j2.render({'values': config_values})
    except Exception as exc:
        logging.error("got exception: %s" % exc)
        return None


def transform_data(config_values, config):
    try:
        spec_str = config['transform']
        spec = json.loads(spec_str)
    except Exception as exc:
        logging.error("could not load spec for transformation. Got %s" % exc)
        return config_values
    return helper.modify_dict(spec, config_values)


def group_device_config(device_config, config, group_pattern, group_by, remove_from_config):

    grouped_config = []
    gc = {}
    groups = set()
    parentheses = r"\(.*\)"
    cleared_config = []

    for named_group in config['named_groups']:
        group_pattern = group_pattern.replace(named_group, config['named_groups'][named_group])

    for block in device_config:
        for line in block:
            match = re.match(group_pattern, line)
            if match:
                groups.add(match.group(group_by))

    for group in groups:
        p = re.sub(parentheses, group, group_pattern)
        gc[group] = []
        for block in device_config:
            for line in block:
                if re.match(p, line):
                    gc[group].append(line)

    # we need a plain list and no dict
    for g in gc:
        grouped_config.append(gc[g])

    # build cleared_config. That is the device_config without the grouped lines
    # loop through all device config lines and check if we have to remove the line
    if remove_from_config:
        for block in device_config:
            for line in block:
                remove_line = False
                for g_block in grouped_config:
                    for g_line in g_block:
                        if g_line == line:
                            remove_line = True
                if not remove_line:
                    cleared_config.append(line)

    # print(json.dumps(cleared_config, indent=4))
    return grouped_config, cleared_config
