import logging
import os.path
from copy import deepcopy

import configparser

logger = logging.getLogger(__name__)

class Config(object):
    default_config = {}

    def __init__(self):
        self._config = configparser.ConfigParser()
        # set defaults
        for k in self.default_config.keys():
            self._config[k] = deepcopy(self.default_config[k])

    def as_dict(self):
        return {s:dict(self._config.items(s)) for s in self._config.sections()}

    def __getattr__(self, item):
        if item in self._config:
            return self._config[item]

    def read(self, config_file):
        self._config.read(config_file)

    def write(self, config_file):
        cfg_dir = os.path.dirname(config_file)
        if not os.path.exists(cfg_dir):
            os.makedirs(cfg_dir)
        with open(config_file, 'w') as f:
            self._config.write(f)

    def update(self, section, dct):
        self._config[section].update(dct)

class VaultConfig(Config):
    rsa_key_len = 4096
    encoding = 'utf-8'
    aes_key_len = 256
    hash_algo = 'sha256'
    block_size = 16
    enc_buf_size = block_size * 10 * 1024

    default_config = {
        'vault': {
            # File patterns to ignore (comma separated list)
            'ignore': '.*,*.encrypted,*.key,.vault',
        },
        'remote': {
            # Protocol to use
            'type': 'binary',

            # Syncrypt server host
            'host': 'prod1.syncrypt.space',
            'port': 1337,
            'ssl': True,

            # How many concurent uploads/downloads we want to
            # support
            'concurrency': 4
        }
    }

    @property
    def id(self):
        return self._config['vault'].get('id', None)

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
        kwargs.pop('type')
        return kwargs

    @property
    def ignore_patterns(self):
        return self._config['vault']['ignore'].split(',')

class AppConfig(Config):
    default_config = {
        'app': {
            'concurrency': 8,
            'vaults': ''
        },
        'api': {
            'host': '127.0.0.1',
            'port': '28080'
        }
    }

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
        a.remove(folder)
        self.vault_dirs = a

class MaterializedAppConfig(AppConfig):
    '''
    An AppConfig that will read and sync the settings from disk.
    '''

    def __init__(self, syncrypt_config_dir=None):
        super(MaterializedAppConfig, self).__init__()

        if syncrypt_config_dir is None:
            self.config_dir = os.path.expanduser('~/.syncrypt')
        else:
            self.config_dir = syncrypt_config_dir

        self.config_file = os.path.join(self.config_dir, 'config')

        logger.debug('Reading application config from %s', self.config_file)

        self.read(self.config_file)

        logger.info('Syncrypt config has %d vault(s).', len(self.vault_dirs))

    def add_vault_dir(self, folder):
        super(MaterializedAppConfig, self).add_vault_dir(folder)
        self.write(self.config_file)

    def remove_vault_dir(self, folder):
        super(MaterializedAppConfig, self).remove_vault_dir(folder)
        self.write(self.config_file)
