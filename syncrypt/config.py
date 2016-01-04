import configparser

class VaultConfig(object):
    rsa_key_len = 1024
    encoding = 'utf-8'
    aes_key_len = 256
    hash_algo = 'sha256'
    iv = 'This is an IV456'
    block_size = 16
    enc_buf_size = block_size * 10 * 1024

    def __init__(self):
        self._config = configparser.ConfigParser()
        # set defaults
        self._config['vault'] = {
                'ignore': '.*,*.encrypted,*.key,.vault',
            }
        self._config['remote'] = {
                'type': 'binary',
                'ssl': True
            }
        self._config['app'] = {
                'concurrency': 8,
            }

    def __getattr__(self, item):
        if item in self._config:
            return self._config[item]

    def read(self, config_file):
        self._config.read(config_file)

    def write(self, config_file):
        with open(config_file, 'w') as f:
            self._config.write(f)

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

