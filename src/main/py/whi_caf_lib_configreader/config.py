import configparser
import os
import re
import caf_logger.logger as caf_logger
import whi_caf_lib_configreader.exceptions as exceptions
from whi_caf_lib_configreader import logging_codes

matching_regex = re.escape('$') + '{.*}'
logger = caf_logger.get_logger('whi-caf-lib-configreader')

_global_secrets_vault = {}


def pre_load_global_secrets(secrets_list_string):
    """
    Pre loading a list of secrets folders. The loaded secrets will be used to interpret the place holders
    in the later config file loading.
    :param secrets_list_string: A string of the comma separated secrets folders being loaded.
                                e.g. /var/app/cassandra/secrets,/var/app/kafka/secrets
    :return: None. Loaded secrets will be kept by the config reader and used in config file loading
    """
    global _global_secrets_vault
    if secrets_list_string:
        secrets_list = [secret.strip() for secret in secrets_list_string.split(',')]
        for secrets_dir in secrets_list:
            _load_secrets_dir(secrets_dir, _global_secrets_vault)


def load_config(config_file, secrets_dir=None):
    """
    Load configurations from a configuration file with sensitive information from secrets folders or
    pre-loaded global secrets.
    :param config_file: a configuration file with secrets being set using place holders following
                        format ${SECRET_ITEM}
    :param secrets_dir: Could be None, a single string or a list of strings. The single string
                        and each item in the list should be a directory. Each file in the directory
                        has the name as the key of the secret and content to be the value.
    :return: successfully loaded configurations. If there are place holders in the config_file, it will
             be replaced with the values read from secrets_dir or from the pre-loaded global secrets
    """
    if (not config_file) or (not os.path.exists(config_file)):
        logger.error(logging_codes.WHI_CAF_LIB_CONFREADER_FILE_NOT_FOUND, config_file)
        raise exceptions.CAFConfigError('File not found')

    logger.info(logging_codes.WHI_CAF_LIB_CONFREADER_LOAD_CONFIG, config_file)
    configfile = configparser.ConfigParser(interpolation=None)
    configfile.optionxform = str
    configfile.read(config_file)

    # Check if there is any secret to be loaded
    local_secrets = _load_local_secrets(secrets_dir) if secrets_dir else {}

    # Check if there is any global secrets loaded already. Combine them if global secrets present.
    # Local secrets take precedence.
    combined_secrets = {**_global_secrets_vault, **local_secrets} if _global_secrets_vault else local_secrets

    # Replace the place holders with the combined key-value map.
    _replace_place_holders(configfile, combined_secrets)

    return configfile


def _load_secrets_dir(secrets_dir, secrets):
    """
    Load secrets from specified folder and store them in the `secrets` object
    :param secrets_dir: A folder containing files with the file name as key and file content as value
    :param secrets: The dictionary to store loaded secrets
    :return: None
    """
    if not os.path.isdir(secrets_dir):
        logger.error(logging_codes.WHI_CAF_LIB_CONFREADER_SECRETS_DIR_NOT_FOUND, secrets_dir)
        raise exceptions.CAFConfigError('Directory not found')

    logger.info(logging_codes.WHI_CAF_LIB_CONFREADER_LOAD_SECRETS, secrets_dir)
    for file_name in os.listdir(secrets_dir):
        file_path = os.path.join(secrets_dir, file_name)
        if os.path.isfile(file_path):
            logger.info(logging_codes.WHI_CAF_LIB_CONFREADER_LOAD_SECRETS_FILE, file_path)
            with open(file_path, 'rt') as fin:
                val = fin.read()
                secrets[file_name] = val


def _load_local_secrets(secrets_dir):
    """
    Load secrets from specified folder or list of folders and return a dictionary containing the secrets key value pairs
    :param secrets_dir: Could be a single string or a list of strings. The single string
                        and each item in the list should be a directory. Each file in the directory
                        has the name as the key of the secret and content to be the value.
    :return: A dictionary containing the secrets key value pairs
    """
    secrets = {}
    if isinstance(secrets_dir, list):
        for secret_dir in secrets_dir:
            _load_secrets_dir(secret_dir, secrets)
    else:
        _load_secrets_dir(secrets_dir, secrets)
    return secrets


def _replace_place_holders(loaded_config_file, place_holders_map):
    """
    Replace place holders in config file using the specified map and validate if all place holders are replaced.
    CAFConfigError will be raised if there are place holders not being replaced.
    :param loaded_config_file: loaded config file which may contains place holders
    :param place_holders_map: The place holder key value dictionary
    :return: None
    """
    for section in loaded_config_file:
        for key, value in loaded_config_file[section].items():
            if re.match(matching_regex, value) is not None:
                secret_name = value[2:-1]
                if secret_name not in place_holders_map:
                    logger.error(logging_codes.WHI_CAF_LIB_CONFREADER_SECRET_NOT_FOUND, secret_name)
                    raise exceptions.CAFConfigError('Secret not found')
                secret_value = place_holders_map[secret_name]
                if secret_value is None:
                    logger.error(logging_codes.WHI_CAF_LIB_CONFREADER_SECRET_NOT_FOUND, secret_name)
                    raise exceptions.CAFConfigError('Secret not found')
                else:
                    loaded_config_file[section][key] = secret_value


def validate_config(configs, section_name, validation_keys):
    # Validate the existence of the section
    if section_name not in configs.sections():
        logger.error(logging_codes.WHI_CAF_LIB_CONFREADER_SECTION_NOT_FOUND, section_name)
        raise exceptions.CAFConfigError('Required section not found')

    # Validate the existence of the required keys under specified section
    valid = True
    for key in validation_keys:
        if key not in configs[section_name]:
            logger.error(logging_codes.WHI_CAF_LIB_CONFREADER_KEYS_MISSING, key, section_name)
            valid = False
    if not valid:
        raise exceptions.CAFConfigError('Configs failed validation')
    else:
        return valid


def get_section(configs, section_name):
    if section_name not in configs.sections():
        logger.error(logging_codes.WHI_CAF_LIB_CONFREADER_SECTION_NOT_FOUND, section_name)
        return
    return configs[section_name]


def get_config_groups(configs, section_name, group_key):
    section = get_section(configs, section_name)
    config_names = str.strip(section.get(group_key, ''))
    if not config_names:
        logger.info(logging_codes.WHI_CAF_LIB_CONFREADER_KEYS_MISSING, group_key, section_name)
        return None
    else:
        group_configs = {}
        config_name_list = [x.strip() for x in config_names.split(',')]
        for config_name in config_name_list:
            config_section = get_section(configs, config_name)
            if not config_section:
                raise exceptions.CAFConfigError('Missing or empty configuration section ' + config_name)
            config_properties = {}
            for key in config_section:
                config_properties[key] = config_section[key]
            group_configs[config_name] = config_properties
        return group_configs
