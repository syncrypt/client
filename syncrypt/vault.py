import hashlib
import logging
import os
import os.path
import sys
from fnmatch import fnmatch
from glob import glob
from pprint import pprint

from syncrypt.utils.filesystem import folder_size
from syncrypt.utils.limiter import JoinableSemaphore

from .bundle import Bundle
from .config import VaultConfig
from .exceptions import SecurityError
from .identity import Identity
from .pipes import Once

logger = logging.getLogger(__name__)

class Vault(object):
    def __init__(self, folder):
        self.folder = folder
        self._bundle_cache = {}
        assert os.path.exists(folder)

        self.config = VaultConfig()
        if os.path.exists(self.config_path):
            logger.info('Using config file: %s', self.config_path)
            self.config.read(self.config_path)
        else:
            self.write_config(self.config_path)

        id_rsa_path = os.path.join(folder, '.vault', 'id_rsa')
        id_rsa_pub_path = os.path.join(folder, '.vault', 'id_rsa.pub')

        self.identity = Identity(id_rsa_path, id_rsa_pub_path, self.config.rsa_key_len)
        self.identity.init()

        Backend = self.config.backend_cls
        kwargs = self.config.backend_kwargs
        # TODO make property?
        self.backend = Backend(self, **kwargs)

        self.semaphores = {
            'update': JoinableSemaphore(32),
            'stat': JoinableSemaphore(32),
            'upload': JoinableSemaphore(32),
            'download': JoinableSemaphore(32)
        }

    @property
    def active(self):
        #print ({k: v.count for (k, v) in self.semaphores.items()})
        return sum(sema.count for sema in self.semaphores.values()) > 0

    def __str__(self):
        return '<Vault: {0} [{1}]>'.format(self.folder, self.state)

    @property
    def crypt_path(self):
        return os.path.join(self.folder, '.vault', 'data')

    @property
    def fileinfo_path(self):
        return os.path.join(self.folder, '.vault', 'fileinfo')

    @property
    def config_path(self):
        return os.path.join(self.folder, '.vault', 'config')

    @property
    def state(self):
        if self.backend.connected:
            return 'syncing' if self.active else 'synced'
        elif self.backend.invalid_auth:
            return 'auth-needed'
        else:
            return 'connecting'

    def write_config(self, config_path=None):
        if config_path is None:
            config_path = self.config_path
        if not os.path.exists(os.path.dirname(config_path)):
            os.makedirs(os.path.dirname(config_path))
        logger.info('Writing config to %s', config_path)
        self.config.write(config_path)

    def get_local_size(self):
        return folder_size(self.folder)

    def get_remote_size(self):
        return 0

    def close(self):
        yield from self.backend.close()

    def walk2(self):
        'a generator of all bundles in this vault'
        # TODO: how to unify with "walk"? should there be a walker
        # that yield both registered and unregistered bundles?
        for f in glob(os.path.join(self.fileinfo_path, '*/*')):
            store_hash = os.path.relpath(f, self.fileinfo_path).replace('/', '')
            if len(store_hash) == 64:
                yield Bundle(None, vault=self, store_hash=store_hash)

    def walk(self, subfolder=None):
        'a generator of all bundles currently present on disk'
        folder = self.folder
        if subfolder:
            folder = os.path.join(folder, subfolder)
        for file in os.listdir(folder):
            if any(fnmatch(file, ig) for ig in self.config.ignore_patterns):
                continue
            abspath = os.path.join(folder, file)
            relpath = os.path.relpath(abspath, self.folder)
            if os.path.isdir(abspath):
                yield from self.walk(subfolder=relpath)
            else:
                yield self.bundle_for(relpath)

    def set_auth(self, username, password):
        self.backend.username = username
        self.backend.password = password

    def clear_bundle_cache(self):
        self._bundle_cache = {}

    def add_bundle_by_fileinfo(self, store_hash, fileinfo):
        bundle = Bundle(None, vault=self, store_hash=store_hash)
        yield from bundle.write_encrypted_fileinfo(Once(fileinfo))

    def bundle_for(self, relpath):
        # check if path should be ignored
        for filepart in relpath.split('/'):
            if any(fnmatch(filepart, ig) for ig in self.config.ignore_patterns):
                return None

        if os.path.isdir(os.path.join(self.folder, relpath)):
            return None

        if not relpath in self._bundle_cache:
            self._bundle_cache[relpath] =\
                    Bundle(os.path.join(self.folder, relpath), vault=self)

        return self._bundle_cache[relpath]

