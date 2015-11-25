import logging
import os
import os.path
import sys
from pprint import pprint

from .bundle import Bundle
from .config import VaultConfig

logger = logging.getLogger(__name__)

class Vault(object):
    def __init__(self, folder):
        self.folder = folder
        config_path = os.path.join(folder, '.vault', 'config')
        assert os.path.exists(folder)
        self.config = VaultConfig()
        if os.path.exists(config_path):
            logger.info('Using config file: %s', config_path)
            self.config.read(config_path)
        else:
            logger.warn('No config found')

    def get_backend_instance(self):
        Backend = self.config.backend_cls
        kwargs = self.config.backend_kwargs
        return Backend(self, **kwargs)

    def walk(self):
        'a generator of all bundles in this vault'
        for (dir, dunno, files) in os.walk(self.folder):
            for f in files:
                if f.endswith('.encrypted') or f.endswith('.key') or f.endswith('.vault'):
                    continue
                abspath = os.path.join(dir, f)
                yield Bundle(abspath, vault=self)
