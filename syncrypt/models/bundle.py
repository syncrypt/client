import hashlib
import sys
import logging
import os
import posixpath

import aiofiles
import asyncio
import umsgpack

from syncrypt.pipes import (Buffered, DecryptAES, DecryptRSA_PKCS1_OAEP, EncryptAES,
                    EncryptRSA_PKCS1_OAEP, FileReader, FileWriter, Hash, Once,
                    PadAES, UnpadAES, SnappyCompress, SnappyDecompress, Count)
from .base import MetadataHolder
from syncrypt.utils.filesystem import splitpath

logger = logging.getLogger(__name__)


class Bundle(MetadataHolder):
    'A Bundle represents a file and some additional information'

    __slots__ = ('path', 'relpath', 'vault', 'file_size', 'file_size_crypt',
            'store_hash', 'crypt_hash', 'remote_crypt_hash', 'uptodate',
            'key', 'bytes_written')

    def __init__(self, abspath, vault, store_hash=None):
        self.vault = vault
        self.path = abspath
        self.uptodate = False
        self.remote_crypt_hash = None
        self.key = None
        self.bytes_written = 0
        self.relpath = None

        if self.path is not None:
            self.relpath = os.path.relpath(self.path, self.vault.folder)
            h = hashlib.new(self.vault.config.hash_algo)
            h.update(self.encode_path(self.relpath))
            self.store_hash = h.hexdigest()
        if store_hash is not None:
            self.store_hash = store_hash

    @property
    def _metadata(self):
        return {
            'filename': self.encode_path(self.relpath),
            'key': self.key,
            'hash': b'\0' * 32,
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
        return self.remote_crypt_hash is None or \
                self.remote_crypt_hash != self.crypt_hash

    async def load_key(self):
        metadata_file = await aiofiles.open(self.path_metadata, 'rb')
        try:
            metadata_contents = await metadata_file.read()
            metadata = umsgpack.loads(metadata_contents)
            self.key = metadata[b'key']
            filename = self.decode_path(metadata[b'filename'])
            if self.path is None:
                self.path = os.path.join(self.vault.folder, filename)
                self.relpath = os.path.relpath(self.path, self.vault.folder)
            else:
                assert self.relpath == filename
            assert len(self.key) == self.key_size
        finally:
            await metadata_file.close()

    async def generate_key(self):
        self.key = os.urandom(self.key_size)
        if not os.path.exists(os.path.dirname(self.path_metadata)):
            os.makedirs(os.path.dirname(self.path_metadata))
        assert len(self.key) == self.key_size

        sink = Once(self.serialized_metadata) >> FileWriter(self.path_metadata)
        await sink.consume()

    def read_encrypted_stream(self):
        assert not self.key is None
        return FileReader(self.path) \
                >> SnappyCompress() \
                >> Buffered(self.vault.config.enc_buf_size) \
                >> PadAES() \
                >> EncryptAES(self.key)

    async def write_encrypted_stream(self, stream, assert_hash=None):
        hash_pipe = Hash(self.vault.config.hash_algo)

        if self.key is None:
            await self.load_key()

        # Security check against malicious path not inside
        vault_path = os.path.abspath(self.vault.folder)
        bundle_path = os.path.abspath(self.path)

        if os.path.commonpath([vault_path]) != os.path.commonpath([vault_path, bundle_path]):
            raise AssertionError("Refusing to write to given bundle path: " + bundle_path)

        sink = stream \
                >> Buffered(self.vault.config.enc_buf_size, self.vault.config.block_size) \
                >> DecryptAES(self.key) \
                >> UnpadAES() \
                >> SnappyDecompress() \
                >> hash_pipe \
                >> FileWriter(self.path, create_dirs=True, create_backup=True, store_temporary=True)

        await sink.consume()

        hash_obj = hash_pipe.hash_obj
        hash_obj.update(self.key)
        received_hash = hash_obj.hexdigest()

        passed = not assert_hash or received_hash == assert_hash

        if not passed:
            logger.error('hash mismatch: {} != {}'.format(assert_hash, received_hash))

        await sink.finalize()

        return passed

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
        except FileNotFoundError:
            await self.generate_key()

        assert self.path is not None

        if os.path.exists(self.path):

            # This will calculate the hash of the file contents
            # As such it will never be sent to the server (see below)
            # TODO: check impact of SnappyCompress and PadAES pipes on
            #       performance. Both are only needed for knowing the
            #       file size in upload. If they have a huge impact on
            #       performance, try to change the protocol so that the
            #       stream size does not need to be known inb4 by the
            #       client source.
            hashing_reader = FileReader(self.path) \
                        >> Hash(self.vault.config.hash_algo)

            counting_reader = hashing_reader \
                        >> SnappyCompress() \
                        >> Buffered(self.vault.config.enc_buf_size) \
                        >> PadAES() \
                        >> Count()
            await counting_reader.consume()

            # We add the AES key to the hash so that the hash stays
            # constant when the files is not changed, but the original
            # hash is also not revealed to the server
            assert len(self.key) == self.key_size
            hash_obj = hashing_reader.hash_obj
            hash_obj.update(self.key)

            self.crypt_hash = hash_obj.hexdigest()

            # Add one time the symmetric block_size to the encrypted file size.
            # This is the length of the IV.
            self.file_size_crypt = counting_reader.count + \
                    self.vault.config.block_size
            self.uptodate = True
        else:
            self.crypt_hash = None
            self.file_size_crypt = None
            self.uptodate = True

    def __str__(self):
        return "<Bundle: {0}>".format(self.relpath)

    @property
    def path_metadata(self):
        return os.path.join(self.vault.bundle_metadata_path, \
                self.store_hash[:2], self.store_hash[2:])


class VirtualBundle(Bundle):
    '''
    A VirtualBundle is a Bundle that will never change anything on the
    filesystem
    '''

    __slots__ = Bundle.__slots__ + ('_virtual_metadata',)

    def __get_metadata(self):
        return self._virtual_metadata

    def __set_metadata(self, metadata):
        self._virtual_metadata = metadata
        if 'filename' in metadata:
            self.relpath = self.decode_path(metadata['filename'])
            self.path = os.path.join(self.vault.folder, self.relpath)

    _metadata = property(__get_metadata, __set_metadata)

    def load_key(self):
        self.key = self._metadata[b'key']

    async def update_serialized_metadata(self, stream):
        await MetadataHolder.update_serialized_metadata(self, stream)

