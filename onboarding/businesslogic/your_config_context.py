from collections import defaultdict
from utilities import utilities


def config_context(result, device_fqdn, device_context, sot_device_context, raw_device_config, onboarding_config):
    """

    Args:
        result:
        device_fqdn:
        device_context:
        sot_device_context:
        raw_device_config:
        onboarding_config:

    Returns:

    """

    """
    
     config = {
        'repo': 'config_contexts',
        'filename': device_fqdn,
        'content': "%s\n%s" % ("---", device_context_as_yaml),
        'action': 'overwrite',
        'pull': False,
    }

    newconfig = {
        "config": config
    }

    result[device_fqdn]['config_context'] = utilities.send_request("editfile",
                                                                onboarding_config["sot"]["api_endpoint"],
                                                                newconfig)
    """

    # write everything you need to "log" to result afterwards
    result[device_fqdn]['userbased_config_context'] = "nothing done"

    return device_context