import asyncio
import configparser
import hashlib
import logging
import os
import os.path
import shutil
import sys
import zipfile
from enum import Enum
from fnmatch import fnmatch
from glob import glob
from io import BytesIO, StringIO

from sqlalchemy import Column, Integer, String, orm

from syncrypt.config import VaultConfig
from syncrypt.exceptions import VaultFolderDoesNotExist, VaultNotInitialized
from syncrypt.pipes import Once
from syncrypt.utils.filesystem import folder_size

from .base import Base, MetadataHolder
from .bundle import Bundle
from .identity import Identity

logger = logging.getLogger(__name__)

IGNORE_EMPTY_FILES = ['.DS_Store']


class VaultState(Enum):
    #UNKNOWN = "unknown"
    UNINITIALIZED = "uninitialized"
    SYNCING = "syncing"
    READY = "ready"
    FAILURE = "failure"


class VaultLoggerAdapter(logging.LoggerAdapter):
    def __init__(self, vault, logger):
        self.vault = vault
        super(VaultLoggerAdapter, self).__init__(logger, {})

    def process(self, msg, kwargs):
        return (msg, dict(kwargs, extra={'vault_id': self.vault.id}))


class Vault(MetadataHolder, Base):
    __tablename__ = 'vault'

    # id: The value to uniquely identify a vault locally. It needs to be a seperate value from
    # the "remote id" because
    # 1) We might clone the same remote id to multiple local vaults (each local vault needs to
    #    be identifyable)
    # 2) We might be in the UNINITIALIZED state, where we don't even know the remote id yet.
    # Still we need to be able to identify the vault.
    id = Column(String(128), primary_key=True)
    folder = Column(String(255))
    byte_size = Column(Integer())
    file_count = Column(Integer())
    modification_date = Column(String(255)) # date?
    revision_count = Column(Integer())
    user_count = Column(Integer())

    def __init__(self, folder):
        self.state = VaultState.UNINITIALIZED
        self.folder = folder
        self._bundle_cache = {}

        self.logger = VaultLoggerAdapter(self, logger)

        hash_obj = hashlib.new('sha256')
        hash_obj.update(os.path.normpath(self.folder).encode())
        self.id = hash_obj.hexdigest()

    @orm.reconstructor
    def init_on_load(self):
        if not hasattr(self, 'state'):
            self.state = VaultState.UNINITIALIZED
        self._bundle_cache = {}
        self.logger = VaultLoggerAdapter(self, logger)

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
            'name': self.config.vault.get('name', ''),
            'icon': self.config.vault.get('icon', None)
        }

    def __set_metadata(self, metadata):
        if 'name' in metadata:
            if self.config.vault['name'] != metadata['name']:
                self.logger.debug('Setting vault\'s name to "%s"', metadata['name'])
                with self.config.update_context():
                    self.config.vault['name'] = metadata['name']
        if 'icon' in metadata and metadata['icon']:
            logger.debug('Setting vault icon')
            with self.config.update_context():
                self.config.vault['icon'] = metadata['icon']

    _metadata = property(__get_metadata, __set_metadata)

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

    # Deprecated
    @property
    def active(self):
        return self.state == VaultState.SYNCING

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

    def get_local_size(self):
        return folder_size(self.folder)

    async def close(self):
        await self.backend.close()

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

    def clear_bundle_cache(self):
        self._bundle_cache = {}

    async def add_bundle_by_metadata(self, store_hash, metadata):
        bundle = Bundle(None, vault=self, store_hash=store_hash)
        await bundle.write_encrypted_metadata(Once(metadata))
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
        self.logger.debug('Update vault revision to "%s"', revision_id)
        with self.config.update_context():
            self.config.update('vault', {'revision': revision_id})

    def package_info(self):
        '''
        return a pipe that will contain vault info such as id, private and
        public key
        '''
        memview = BytesIO()
        zipf = zipfile.ZipFile(memview, 'w', zipfile.ZIP_DEFLATED)

        cloned_config = configparser.ConfigParser()
        cloned_config.read_dict(self.config._config)

        # include config but strip auth information
        if 'remote' in cloned_config:
            for key in ('auth', 'username', 'password'):
                if key in cloned_config['remote']:
                    del cloned_config['remote'][key]

        # also vault info such as revision
        if 'vault' in cloned_config:
            for key in ('revision',):
                if key in cloned_config['vault']:
                    del cloned_config['vault'][key]

        temp_config = StringIO()
        cloned_config.write(temp_config)
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

        logger.info("Creating vault from package in %s", local_directory)

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

    async def delete(self):
        config_folder = os.path.join(self.folder, '.vault')
        logger.info('Removing the vault metadata folder: %s', config_folder)
        # TODO: this should be done in a process (could take a while for big vaults)
        shutil.rmtree(config_folder, ignore_errors=True)
        self.state = VaultState.UNINITIALIZED
