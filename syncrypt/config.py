import configparser
from copy import deepcopy

class VaultConfig(object):
    rsa_key_len = 1024
    encoding = 'utf-8'
    aes_key_len = 256
    hash_algo = 'sha256'
    block_size = 16
    rsa_dec_block_size = 128
    rsa_enc_block_size = 117
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
        },
        'app': {
            'concurrency': 8,
        },
        'api': {
            'host': '127.0.0.1',
            'port': '28080'
        }
    }

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
        with open(config_file, 'w') as f:
            self._config.write(f)

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

    def update(self, section, dct):
        self._config[section].update(dct)

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

