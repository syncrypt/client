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
from syncrypt.exceptions import SecurityError, VaultNotInitialized, VaultFolderDoesNotExist
from syncrypt.pipes import Once
from syncrypt.utils.filesystem import folder_size
from syncrypt.utils.semaphores import JoinableSetSemaphore

from .base import MetadataHolder
from .bundle import Bundle
from .identity import Identity

logger = logging.getLogger(__name__)

IGNORE_EMPTY_FILES = ['.DS_Store']

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
            self.check_existence()
            self._config = VaultConfig(self.config_path)
            return self._config

    def __get_metadata(self):
        return {
            'name': self.config.vault.get('name', '')
        }

    def __set_metadata(self, metadata):
        if 'name' in metadata:
            logger.debug('Setting vault\'s name to "%s"', metadata['name'])
            with self.config.update_context():
                self.config.vault['name'] = metadata['name']

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
        #logger.debug('Sema count: %s', [sema.count for sema in self.semaphores.values()])
        return sum(sema.count for sema in self.semaphores.values()) > 0

    def __str__(self):
        return '<Vault: {0}>'.format(self.folder)

    def __repr__(self):
        return 'syncrypt.models.Vault(\'{0}\')'.format(self.folder)

    def check_existence(self):
        if not os.path.exists(self.folder):
            raise VaultFolderDoesNotExist()

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
        return 'syncing' if self.active else 'synced'

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

    def set_global_auth(self, global_auth):
        self.backend.global_auth = global_auth

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
        with self.config.update_context():
            self.config.update('vault', {'revision': revision_id})

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

        logger.info("Trying to create vault from package in %s", local_directory)

        try:
            os.makedirs(local_directory)
        except FileExistsError:
            logger.debug("Directory exists, checking if empty")
            entities = os.listdir(local_directory)
            for entity in entities:
                entity_path = os.path.join(local_directory, entity)
                if os.path.isfile(entity_path) or os.path.isdir(entity_path):
                    if not entity in IGNORE_EMPTY_FILES:
                        raise IOError('Directory "%s" already exists and is not empty.' % local_directory)

        zipf = zipfile.ZipFile(BytesIO(package_info), 'r')
        zipf.extractall(path=local_directory)
        vault = Vault(local_directory)

        if auth_token:
            with vault.config.update_context():
                vault.config.update('remote', {'auth': auth_token})

        return vault

