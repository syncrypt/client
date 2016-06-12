import hashlib
import logging
import os
import os.path
import sys
import zipfile
from fnmatch import fnmatch
from glob import glob
from io import BytesIO, StringIO

import asyncio
from syncrypt.config import VaultConfig
from syncrypt.exceptions import SecurityError, VaultNotInitialized
from syncrypt.pipes import Once
from syncrypt.utils.filesystem import folder_size
from syncrypt.utils.semaphores import JoinableSetSemaphore

from .base import MetadataHolder
from .bundle import Bundle
from .identity import Identity

logger = logging.getLogger(__name__)

class Vault(MetadataHolder):
    def __init__(self, folder):
        self.folder = folder
        self._bundle_cache = {}

        self.semaphores = {
            'update': JoinableSetSemaphore(32),
            'stat': JoinableSetSemaphore(32),
            'upload': JoinableSetSemaphore(32),
            'download': JoinableSetSemaphore(32)
        }

    @property
    def config(self):
        try:
            return self._config
        except AttributeError:
            assert os.path.exists(self.folder)
            self._config = VaultConfig()
            if os.path.exists(self.config_path):
                logger.debug('Using config file: %s', self.config_path)
                self._config.read(self.config_path)
            else:
                raise VaultNotInitialized(self.folder)
            return self._config

    def __get_metadata(self):
        return {
            'name': self.config.vault.get('name', '')
        }

    def __set_metadata(self, metadata):
        if 'name' in metadata:
            logger.debug('Setting vault\'s name to "%s"', metadata['name'])
            self.config.vault['name'] = metadata['name']
            self.write_config()

    metadata = property(__get_metadata, __set_metadata)

    @property
    def identity(self):
        try:
            return self._identity
        except AttributeError:
            id_rsa_path = os.path.join(self.folder, '.vault', 'id_rsa')
            id_rsa_pub_path = os.path.join(self.folder, '.vault', 'id_rsa.pub')
            self._identity = Identity(id_rsa_path, id_rsa_pub_path, self.config)
            return self._identity

    @property
    def backend(self):
        try:
            return self._backend
        except AttributeError:
            Backend = self.config.backend_cls
            kwargs = self.config.backend_kwargs
            self._backend = Backend(self, **kwargs)
            return self._backend

    @property
    def active(self):
        return sum(sema.count for sema in self.semaphores.values()) > 0

    def __str__(self):
        return '<Vault: {0}>'.format(self.folder)

    @property
    def crypt_path(self):
        return os.path.join(self.folder, '.vault', 'data')

    @property
    def bundle_metadata_path(self):
        return os.path.join(self.folder, '.vault', 'metadata')

    @property
    def revision(self):
        return self.config.vault['revision'] if 'revision' in self.config.vault else None

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
        logger.debug('Writing config to %s', config_path)
        self.config.write(config_path)

    def get_local_size(self):
        return folder_size(self.folder)

    def get_remote_size(self):
        return 0

    def close(self):
        yield from self.backend.close()

    def walk(self):
        '''
        A generator of all registered bundles in this vault
        '''
        for f in glob(os.path.join(self.bundle_metadata_path, '??/*')):
            store_hash = os.path.relpath(f, self.bundle_metadata_path).replace('/', '')
            if len(store_hash) == 64:
                yield Bundle(None, vault=self, store_hash=store_hash)

    def walk_disk(self, subfolder=None):
        '''
        A generator of all bundles currently present on disk in this vault
        '''
        folder = self.folder
        if subfolder:
            folder = os.path.join(folder, subfolder)
        for file in os.listdir(folder):
            if any(fnmatch(file, ig) for ig in self.config.ignore_patterns):
                continue
            abspath = os.path.join(folder, file)
            relpath = os.path.relpath(abspath, self.folder)
            if os.path.isdir(abspath):
                yield from self.walk_disk(subfolder=relpath)
            else:
                yield self.bundle_for(relpath)

    def set_auth(self, username, password):
        self.backend.username = username
        self.backend.password = password

    def clear_bundle_cache(self):
        self._bundle_cache = {}

    @asyncio.coroutine
    def add_bundle_by_metadata(self, store_hash, metadata):
        bundle = Bundle(None, vault=self, store_hash=store_hash)
        yield from bundle.write_encrypted_metadata(Once(metadata))
        return bundle

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

    def update_revision(self, revision_id):
        if isinstance(revision_id, bytes):
            revision_id = revision_id.decode(self.config.encoding)
        logger.debug('Update vault revision to "%s"', revision_id)
        self.config.update('vault', {'revision': revision_id})
        self.write_config()

    def package_info(self):
        '''
        return a pipe that will contain vault info such as id, private and
        public key
        '''
        memview = BytesIO()
        zipf = zipfile.ZipFile(memview, 'w', zipfile.ZIP_DEFLATED)

        # include config but strip auth information
        self.config.unset('remote.auth')
        self.config.unset('remote.username')
        self.config.unset('remote.password')

        # also strip revision
        self.config.unset('vault.revision')

        temp_config = StringIO()
        self.config._config.write(temp_config)
        temp_config.seek(0)
        zipf.writestr('.vault/config', temp_config.read().encode(self.config.encoding))

        # include private and public key
        def include(f):
            zipf.write(f, arcname=os.path.relpath(f, self.folder))
        include(self.identity.id_rsa_path)
        include(self.identity.id_rsa_pub_path)

        zipf.close()

        memview.seek(0)
        return Once(memview.read())

    @staticmethod
    def from_package_info(package_info, local_directory, auth_token=None):
        try:
            os.makedirs(local_directory)
        except FileExistsError:
            raise IOError('Directory "%s" already exists.' % local_directory)

        zipf = zipfile.ZipFile(BytesIO(package_info), 'r')
        zipf.extractall(path=local_directory)
        vault = Vault(local_directory)

        if auth_token:
            vault.config.update('remote', {'auth': auth_token})
            vault.write_config()

        return vault

