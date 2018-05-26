import logging
import os.path
from copy import deepcopy

import configparser

logger = logging.getLogger(__name__)


class Config(object):
    rsa_key_len = 4096
    encoding = 'utf-8'
    hash_algo = 'sha256'

    # Whenever we display fingerprints of keys, this describes how many
    # characters we show of the hexadecimal representation
    fingerprint_length = 16

    default_config = {}

    def __init__(self, config_path=None):
        self._config = configparser.ConfigParser()
        if config_path is None:
            config_path = os.path.join(self.config_dir, 'config')
        self._config_path = os.path.abspath(config_path)
        # set defaults
        for k in self.default_config.keys():
            self._config[k] = deepcopy(self.default_config[k])
        self.read()

    def as_dict(self):
        return {s:dict(self._config.items(s)) for s in self._config.sections()}

    def __getattr__(self, item):
        if item in self._config:
            return self._config[item]

    def update_context(self):
        return self

    def __enter__(self):
        self.read()

    def __exit__(self, ex_type, ex_val, tb):
        self.write()

    def read(self):
        if os.path.exists(self._config_path):
            self._config.read(self._config_path, encoding='utf-8')

    def write(self):
        cfg_dir = os.path.dirname(self._config_path)
        if not os.path.exists(cfg_dir):
            os.makedirs(cfg_dir)
        with open(self._config_path, 'w') as f:
            self._config.write(f)

    def get(self, setting, default=None):
        realm, setting_ = setting.split('.')
        return self._config[realm].get(setting_, default)

    def set(self, setting, value):
        realm, setting_ = setting.split('.')
        self._config[realm][setting_] = value
        #logger.debug('Setting config: %s.%s = %s', realm, setting_, value)

    def unset(self, setting):
        realm, setting_ = setting.split('.')
        if setting_ in self._config[realm]:
            del self._config[realm][setting_]
        #logger.debug('Unsetting config: %s.%s', realm, setting_)

    def update(self, section, dct):
        self._config[section].update(dct)
        #logger.debug('Update vault config: %s <- %s', section, dct)

    @property
    def config_dir(self):
        if hasattr(self, '_config') and 'app' in self._config \
                and 'directory' in self._config['app']:
            return self._config['app']['directory']
        else:
            return os.path.join(os.path.expanduser('~'), '.config', 'syncrypt')


class BackendConfigMixin():
    DEFAULT_BACKEND_CFG = {
        # Protocol to use
        'type': 'binary',

        # Syncrypt server host
        'host': 'storage.syncrypt.space',
        'port': 1337,
        'ssl': True,
        'ssl_verify': True,

        # Maximum number of concurent connections
        'concurrency': 10,
    }

    @property
    def backend_cls(self):
        if self._config['remote']['type'] == 'local':
            from .backends import LocalStorageBackend
            return LocalStorageBackend
        elif self._config['remote']['type'] == 'binary':
            from .backends import BinaryStorageBackend
            return BinaryStorageBackend
        else:
            raise Exception(self._config['remote']['type'])

    @property
    def backend_kwargs(self):
        kwargs = dict(self._config['remote']) # copy dict
        if 'ssl' in kwargs and kwargs['type'] == 'binary':
            kwargs['ssl'] = not (kwargs['ssl'].lower() in ['no', 'false', '0'])
        else:
            del kwargs['ssl']
        if 'ssl_verify' in kwargs and kwargs['type'] == 'binary':
            kwargs['ssl_verify'] = not (kwargs['ssl_verify'].lower() in ['no', 'false', '0'])
        else:
            del kwargs['ssl_verify']
        kwargs.pop('type')
        kwargs['concurrency'] = self.DEFAULT_BACKEND_CFG['concurrency']
        return kwargs


class VaultConfig(Config, BackendConfigMixin):
    aes_key_len = 256
    block_size = 16
    enc_buf_size = block_size * 10 * 1024

    # This list contains file patterns that we will always ignore. If an item
    # was removed from this list, syncrypt will not function as expected.
    # See below for a list of user-defineable ignore patterns
    hard_ignore = ['.vault', '*.scbackup', '*.sctemp*']

    default_config = {
        'vault': {
            # File patterns to ignore (comma separated list)
            'ignore': '.*',
            'name': '',
            'pull_interval': 300
        },
        'remote': BackendConfigMixin.DEFAULT_BACKEND_CFG
    }

    @property
    def id(self):
        # Maybe this should be removed to avoid confusion
        return self._config['vault'].get('id', None)

    @property
    def ignore_patterns(self):
        return self._config['vault']['ignore'].split(',') + self.hard_ignore


class AppConfig(Config, BackendConfigMixin):
    default_config = {
        'app': {
            'concurrency': 6,
            'vaults': ''
        },
        'gui': {
            'is_first_launch': '1',
            'language': 'English'
        },
        'api': {
            'host': '127.0.0.1',
            'port': '28080',
            'auth_token': ''
        },
        'store': {
            'engine': 'sqlite',
            'path': 'syncrypt.db'
        },
        'remote': BackendConfigMixin.DEFAULT_BACKEND_CFG
    }

    def __init__(self, config_file=None):
        super(AppConfig, self).__init__(config_file)
        logger.info('Syncrypt config has %d vault(s).', len(self.vault_dirs))

    @property
    def vault_dirs(self):
        value = self._config.get('app', 'vaults')
        return list(filter(None, (x.strip() for x in value.splitlines())))

    @vault_dirs.setter
    def vault_dirs(self, dirs):
        self._config.set('app', 'vaults', '\n' + '\n'.join(dirs))

    def add_vault_dir(self, folder):
        self.vault_dirs = list(set(self.vault_dirs + [folder]))

    def remove_vault_dir(self, folder):
        a = self.vault_dirs
        try:
            a.remove(folder)
        except ValueError:
            pass
        self.vault_dirs = a
