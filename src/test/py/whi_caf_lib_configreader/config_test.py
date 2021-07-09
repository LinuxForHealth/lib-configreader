import os
import unittest

from whi_caf_lib_configreader import config
from whi_caf_lib_configreader import exceptions


def get_resource_path(file_name):
    package_directory = os.path.dirname(os.path.abspath(__file__))
    root_path = "/../../resources"
    file = os.path.join(package_directory + root_path, file_name)
    return file


def _get_file_content(secret_file):
    with open(secret_file, 'rt') as fin:
        return fin.read()


class TestConfigMethods(unittest.TestCase):

    def setUp(self) -> None:
        self.config_file = get_resource_path('sample_config.ini')
        self.redis_secrets_dir = get_resource_path('secrets/redis')
        self.liberty_secrets_dir = get_resource_path('secrets/liberty')
        self.cassandra_secrets_dir = get_resource_path('secrets/cassandra')

    def test_load_config(self):
        # success
        configs = config.load_config(self.config_file, self.redis_secrets_dir)
        self.assertIsNotNone(configs)

        # fail
        with self.assertRaises(exceptions.CAFConfigError):
            config.load_config('bad/file/path', self.redis_secrets_dir)

        with self.assertRaises(exceptions.CAFConfigError):
            config.load_config(None)

    def test_pre_load_secrets(self):
        config.pre_load_global_secrets(
            "{},{},{}".format(self.redis_secrets_dir, self.cassandra_secrets_dir, self.liberty_secrets_dir))

        sample_config_2 = get_resource_path('sample_config2.ini')
        configs = config.load_config(sample_config_2)
        self._verify_sample_config2_loaded(configs)

        # Test loading fail if missing secrets
        config._global_secrets_vault = {}
        self.assertFalse(config._global_secrets_vault)
        config.pre_load_global_secrets(
            "{},{}".format(self.redis_secrets_dir, self.cassandra_secrets_dir))
        with self.assertRaises(exceptions.CAFConfigError):
            config.load_config(sample_config_2)

        config._global_secrets_vault = {}
        config.pre_load_global_secrets('')
        with self.assertRaises(exceptions.CAFConfigError):
            config.load_config(sample_config_2)

        # Test partially global secrets and partially local secrets
        config._global_secrets_vault = {}
        self.assertFalse(config._global_secrets_vault)
        config.pre_load_global_secrets(
            "{},{}".format(self.redis_secrets_dir, self.cassandra_secrets_dir))
        configs = config.load_config(sample_config_2, self.liberty_secrets_dir)
        self._verify_sample_config2_loaded(configs)

    def _verify_sample_config2_loaded(self, configs):
        secret_value = _get_file_content(get_resource_path('secrets/cassandra/WHI_CAF_KEYSPACE_PASSWORD'))
        self.assertEqual(configs['NIFI']['WHI_CAF_KEYSPACE_PASSWORD'], secret_value)
        secret_value = _get_file_content(get_resource_path('secrets/liberty/LIBERTYBASE_KEYSTORE_PASSWORD'))
        self.assertEqual(configs['NIFI']['LIBERTYBASE_KEYSTORE_PASSWORD'], secret_value)
        secret_value = _get_file_content(get_resource_path('secrets/redis/WHI_CAF_REDIS_PASSWORD'))
        self.assertEqual(configs['REDIS']['WHI_CAF_REDIS_PASSWORD'], secret_value)

    def test_load_secrets(self):
        # success
        secret_value = _get_file_content(get_resource_path('secrets/redis/WHI_CAF_REDIS_PASSWORD'))
        configs = config.load_config(self.config_file, self.redis_secrets_dir)
        self.assertEqual(configs['REDIS']['WHI_CAF_REDIS_PASSWORD'], secret_value)

        # missing secret
        configs['REDIS']['WHI_CAF_REDIS_PASSWORD'] = '${MISSING_SECRET}'
        with self.assertRaises(exceptions.CAFConfigError):
            local_secrets = config._load_local_secrets(self.redis_secrets_dir)
            config._replace_place_holders(configs, local_secrets)

        # Test loading list of secrets
        # Make sure there are no previous loaded global secrets
        config._global_secrets_vault = {}
        secrets = [self.redis_secrets_dir, self.cassandra_secrets_dir, self.liberty_secrets_dir]
        configs = config.load_config(get_resource_path('sample_config2.ini'), secrets)
        self.assertEqual(configs['NIFI']['WHI_CAF_KEYSPACE_PASSWORD'], 'cassandra')

    def test_validate_config(self):
        # success
        configs = config.load_config(self.config_file, self.redis_secrets_dir)
        self.assertTrue(config.validate_config(configs, 'REDIS', ['WHI_CAF_REDIS_HOST', 'WHI_CAF_REDIS_PORT']))

        # fail
        configs = config.load_config(get_resource_path('bad_config.ini'), self.redis_secrets_dir)
        with self.assertRaises(exceptions.CAFConfigError):
            config.validate_config(configs, 'REDIS', ['WHI_CAF_REDIS_HOST', 'WHI_CAF_REDIS_PORT'])

        # fail, required section doesn't exist
        with self.assertRaises(exceptions.CAFConfigError):
            config.validate_config(configs, 'TEST_NONEXIST_SECTION', ['WHI_CAF_REDIS_HOST', 'WHI_CAF_REDIS_PORT'])

    def test_get_section(self):
        configs = config.load_config(self.config_file, self.redis_secrets_dir)
        self.assertIsNotNone(config.get_section(configs, 'REDIS'))
        self.assertIsNone(config.get_section(configs, 'SIDER'))

    def test_get_config_groups(self):
        configs = config.load_config(self.config_file, self.redis_secrets_dir)
        config_group = config.get_config_groups(configs, 'REDIS', 'WHI_CAF_TEST_GROUP')
        self.assertIsNotNone(config_group)
        self.assertEqual(len(config_group), 2)

        config_group = config.get_config_groups(configs, 'REDIS', 'NON_EXISTENT_GROUP')
        self.assertIsNone(config_group)

    def test_interpolation(self):
        configs = config.load_config(get_resource_path('special_char_config.ini'))
        self.assertEqual(configs['REDIS']['WHI_CAF_PASSWORD'], 'sasd33fFDDF%fsdfsd')
