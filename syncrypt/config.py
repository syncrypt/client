import configparser

class VaultConfig(object):

    def __init__(self):
        self._config = configparser.ConfigParser()

    def read(self, config_file):
        self._config.read(config_file)

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
        kwargs.pop('type')
        return kwargs

