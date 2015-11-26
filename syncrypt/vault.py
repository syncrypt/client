import logging
import os
import os.path
import sys
from pprint import pprint

from Crypto.PublicKey import RSA

from .bundle import Bundle
from .config import VaultConfig

logger = logging.getLogger(__name__)

class Vault(object):
    def __init__(self, folder):
        self.folder = folder
        assert os.path.exists(folder)

        config_path = os.path.join(folder, '.vault', 'config')
        self.config = VaultConfig()
        if os.path.exists(config_path):
            logger.info('Using config file: %s', config_path)
            self.config.read(config_path)
        else:
            self.init_config(config_path)

        id_rsa_path = os.path.join(folder, '.vault', 'id_rsa')
        id_rsa_pub_path = os.path.join(folder, '.vault', 'id_rsa.pub')
        if not os.path.exists(id_rsa_path) or not os.path.exists(id_rsa_pub_path):
            self.init_keys(id_rsa_path, id_rsa_pub_path)
        else:
            self.public_key = RSA.importKey(open(id_rsa_pub_path, 'rb').read())
            self.private_key = RSA.importKey(open(id_rsa_path, 'rb').read())

    def init_config(self, config_path):
        if not os.path.exists(os.path.dirname(config_path)):
            os.makedirs(os.path.dirname(config_path))
        logger.info('Writing config to %s', config_path)
        self.config.write(config_path)

    def init_keys(self, id_rsa_path, id_rsa_pub_path):
        if not os.path.exists(os.path.dirname(id_rsa_path)):
            os.makedirs(os.path.dirname(id_rsa_path))
        logger.info('Generating RSA key pair...')
        keys = RSA.generate(self.config.rsa_key_len)
        with open(id_rsa_pub_path, 'wb') as id_rsa_pub:
            id_rsa_pub.write(keys.publickey().exportKey())
        with open(id_rsa_path, 'wb') as id_rsa:
            id_rsa.write(keys.exportKey())
        self.private_key = keys
        self.public_key = keys.publickey()

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
