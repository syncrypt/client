import hashlib
import logging
import os
import posixpath
from typing import Optional

import trio
import umsgpack
from sqlalchemy import Column, ForeignKey, Integer, LargeBinary, String, orm
from sqlalchemy.orm import relationship

from syncrypt.exceptions import InvalidBundleKey, InvalidBundleMetadata
from syncrypt.pipes import FileWriter, Once
from syncrypt.utils.filesystem import splitpath

from .base import Base, MetadataHolder

logger = logging.getLogger(__name__)

VERBOSE_DEBUG = False


class Bundle(MetadataHolder, Base):
    'A Bundle represents a file and some additional information'
    __tablename__ = 'bundle'

    # TODO normally these fields should only be set when applying the revsion
    # do we need an extra model to deal with local size/hash etc.?
    id = Column(Integer(), primary_key=True)
    vault_id = Column(String(128), ForeignKey("vault.id"))
    vault = relationship("Vault", foreign_keys=[vault_id], lazy='noload')
    relpath = Column(String(512), nullable=False)
    file_size = Column(Integer())
    store_hash = Column(String(128), nullable=False)
    hash = Column(String(128), nullable=False)
    key = Column(LargeBinary(512)) # AES key used

    #__slots__ = ('path', 'relpath', 'vault', 'file_size', 'file_size_crypt',
    #        'store_hash', 'crypt_hash', 'uptodate',
    #        'key', 'bytes_written')

    def __init__(self, *args, **kwargs):
        super(Bundle, self).__init__(*args, **kwargs)
        self.uptodate = False
        self.local_hash = None # type: Optional[str]
        self.bytes_written = 0

    @orm.reconstructor
    def init_on_load(self):
        self.uptodate = False
        self.bytes_written = 0
        self.local_hash = None
        self.relpath = self.relpath.decode() # why is this binary?!

    def update_store_hash(self):
        h = hashlib.new(self.vault.config.hash_algo)
        h.update(self.encode_path(self.relpath))
        self.store_hash = h.hexdigest()

    def __hash__(self):
        return hash(self.vault_id + self.relpath)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Bundle):
            return NotImplemented
        return self.vault_id == other.vault_id and self.relpath == other.relpath

    @property
    def _metadata(self):
        return {
            'filename': self.encode_path(self.relpath),
            'key': self.key,
            'hash': self.local_hash,
            'file_size': self.file_size,
            'key_size': self.key_size
        }

    @property
    def key_size(self):
        return self.vault.config.aes_key_len >> 3

    @property
    def identity(self):
        return self.vault.identity

    def encode_path(self, relpath):
        "Encodes a relative path into POSIX path bytes"
        # TODO: on POSIX systems, the path conversion could be skipped for performance
        relpath = posixpath.join(*splitpath(relpath))
        return relpath.encode(self.vault.config.encoding, 'surrogateescape')

    def decode_path(self, relpath):
        "Decodes a POSIX path in bytes into a relative path"
        # TODO: on POSIX systems, the path conversion could be skipped for performance
        if isinstance(relpath, bytes):
            relpath = relpath.decode(self.vault.config.encoding, 'surrogateescape')
        return os.path.join(*splitpath(relpath, pathmod=posixpath))

    @property
    def remote_hash_differs(self):
        if VERBOSE_DEBUG:
            logger.debug('Remote hash: %s', self.hash)
            logger.debug('Local hash:  %s', self.local_hash)
        return self.hash is None or self.hash != self.local_hash

    async def load_key(self):
        async with await trio.open_file(self.path_metadata, 'rb') as md_file:
            metadata_contents = await md_file.read()  # type: ignore

        metadata = umsgpack.loads(metadata_contents)

        if not isinstance(metadata, dict):
            raise InvalidBundleMetadata()

        if not 'key' in metadata or not metadata['key']:
            logger.warning('No or invalid key found for %s in metadata: %s', self, metadata)
            raise InvalidBundleKey()

        self.key = metadata['key']
        self.relpath = self.decode_path(metadata['filename'])
        assert len(self.key) == self.key_size

    @property
    def path(self):
        return os.path.join(self.vault.folder, self.relpath)

    async def generate_key(self):
        logger.debug('Generating key for %s', self)
        self.key = os.urandom(self.key_size)
        if not os.path.exists(os.path.dirname(self.path_metadata)):
            os.makedirs(os.path.dirname(self.path_metadata))
        assert len(self.key) == self.key_size

        sink = Once(self.serialized_metadata) >> FileWriter(self.path_metadata)
        await sink.consume()

    async def update_serialized_metadata(self, stream):
        logger.debug("Updating metadata on disk")
        sink = stream >> FileWriter(self.path_metadata, create_dirs=True)
        await sink.consume()
        assert os.path.exists(self.path_metadata)

    async def update(self):
        'update encrypted hash (store in .vault)'

        #logger.info('Updating %s', self)

        try:
            await self.load_key()
        except (FileNotFoundError, InvalidBundleKey):
            await self.generate_key()

        assert self.path is not None

        if os.path.exists(self.path):
            self.local_hash, self.file_size_crypt = \
                await self.vault.crypt_engine.get_crypt_hash_and_size(self)
            self.uptodate = True
        else:
            self.local_hash = None
            self.file_size_crypt = None
            self.uptodate = True

    def __str__(self):
        return "<Bundle: {0}>".format(self.relpath)

    @property
    def path_metadata(self):
        return os.path.join(self.vault.bundle_metadata_path, \
                self.store_hash[:2], self.store_hash[2:])



#class VirtualBundle(object):
#    '''
#    A VirtualBundle is a Bundle that will never change anything on the
#    filesystem
#    '''
#    __tablename__ = 'virtual_bundle'
#
#   #__slots__ = Bundle.__slots__ + ('_virtual_metadata',)
#
#    def __get_metadata(self):
#        return self._virtual_metadata
#
#    def __set_metadata(self, metadata):
#        self._virtual_metadata = metadata
#        if 'filename' in metadata:
#            self.relpath = self.decode_path(metadata['filename'])
#            self.path = os.path.join(self.vault.folder, self.relpath)
#
#    _metadata = property(__get_metadata, __set_metadata)
#
#    def load_key(self):
#        self.key = self._metadata[b'key']
#
#    async def update_serialized_metadata(self, stream):
#        await MetadataHolder.update_serialized_metadata(self, stream)
