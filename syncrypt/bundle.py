import hashlib
import logging
import os

import Crypto.Util.number
from Crypto.Cipher import AES

import aiofiles
import asyncio
import umsgpack

from .pipes import (Buffered, Decrypt, DecryptRSA, Encrypt, EncryptRSA,
                    FileReader, FileWriter, Hash, Once, SnappyCompress,
                    SnappyDecompress)

logger = logging.getLogger(__name__)

class Bundle(object):
    'A Bundle represents a file and some additional information'

    encrypt_semaphore = asyncio.Semaphore(value=8)
    decrypt_semaphore = asyncio.Semaphore(value=8)

    __slots__ = ('path', 'vault', 'file_size', 'file_size_crypt',
            'key_size_crypt', 'store_hash', 'crypt_hash',
            'remote_crypt_hash', 'uptodate', 'update_handle', 'key')

    def __init__(self, abspath, vault, store_hash=None):
        self.vault = vault
        self.path = abspath
        self.uptodate = False
        self.remote_crypt_hash = None
        self.update_handle = None

        if self.path is not None:
            h = hashlib.new(self.vault.config.hash_algo)
            h.update(self.relpath.encode(self.vault.config.encoding))
            self.store_hash = h.hexdigest()
        if store_hash is not None:
            self.store_hash = store_hash

    def populate_from_fileinfo(self):
        pass

    @property
    def bundle_size(self):
        return len(self.serialized_bundle)

    @property
    def serialized_bundle(self):
        return umsgpack.dumps(self.bundle)

    @property
    def bundle(self):
        return {
            'filename': os.path.relpath(self.path, self.vault.folder),
            'key': self.key,
            'hash': b'\0' * 32,
            'key_size': self.key_size
        }

    @property
    def key_size(self):
        return self.vault.config.aes_key_len >> 3

    @property
    def remote_hash_differs(self):
        return self.remote_crypt_hash is None or \
                self.remote_crypt_hash != self.crypt_hash

    @asyncio.coroutine
    def load_key(self):
        key_file = yield from aiofiles.open(self.path_fileinfo, 'rb')
        try:
            encrypted_key = yield from key_file.read()
            fileinfo = umsgpack.loads(encrypted_key)
            self.key = fileinfo[b'key']
            self.key_size_crypt = len(encrypted_key)
            assert len(self.key) == self.key_size
        finally:
            yield from key_file.close()

    @asyncio.coroutine
    def generate_key(self):
        self.key = os.urandom(self.key_size)
        if not os.path.exists(os.path.dirname(self.path_fileinfo)):
            os.makedirs(os.path.dirname(self.path_fileinfo))
        assert len(self.key) == self.key_size

        sink = Once(self.serialized_bundle) >> FileWriter(self.path_fileinfo)
        yield from sink.consume()

    def encrypted_fileinfo_reader(self):
        return Once(self.serialized_bundle) \
                >> SnappyCompress() \
                >> Buffered(self.vault.config.rsa_enc_block_size) \
                >> EncryptRSA(self)

    def read_encrypted_stream(self):
        return FileReader(self.path) \
                >> SnappyCompress() \
                >> Buffered(self.vault.config.enc_buf_size) \
                >> Encrypt(self)

    @asyncio.coroutine
    def write_encrypted_stream(self, stream, assert_hash=None):
        hash_pipe = Hash(self)

        sink = stream \
                >> Buffered(self.vault.config.enc_buf_size) \
                >> hash_pipe \
                >> Decrypt(self) \
                >> SnappyDecompress() \
                >> FileWriter(self.path)

        yield from sink.consume()

        if assert_hash and hash_pipe.hash != assert_hash:
            # TODO: restore original file and alert server
            raise Exception('hash mismatch!')

    @asyncio.coroutine
    def write_encrypted_fileinfo(self, stream):
        logger.info("Updating fileinfo on disk")
        sink = stream \
                >> Buffered(self.vault.config.rsa_dec_block_size) \
                >> DecryptRSA(self) \
                >> SnappyDecompress() \
                >> FileWriter(self.path_fileinfo)

        yield from sink.consume()
        assert os.path.exists(self.path_fileinfo)

    @asyncio.coroutine
    def update(self):
        'update encrypted hash (store in .vault)'

        yield from self.encrypt_semaphore.acquire()
        logger.info('Updating %s', self)

        if self.path is None:
            yield from self.bundle.populate_from_fileinfo()
            assert self.path is not None

        try:
            yield from self.load_key()
        except FileNotFoundError:
            yield from self.generate_key()

        hashing_reader = self.read_encrypted_stream() >> Hash(self)
        yield from hashing_reader.consume()

        self.crypt_hash = hashing_reader.hash
        self.file_size_crypt = hashing_reader.size
        self.uptodate = True
        self.encrypt_semaphore.release()

    def update_and_upload(self):
        backend = self.vault.backend
        def x(bundle):
            yield from bundle.update()
            yield from backend.stat(bundle)
            if bundle.remote_hash_differs:
                yield from backend.upload(bundle)
        asyncio.ensure_future(x(self))

    def schedule_update(self):
        if self.update_handle:
            self.update_handle.cancel()
        loop = asyncio.get_event_loop()
        self.update_handle = loop.call_later(1.0, self.update_and_upload)

    def __str__(self):
        return "<Bundle: {0.relpath}>".format(self)

    @property
    def relpath(self):
        return os.path.relpath(self.path, self.vault.folder)

    @property
    def path_fileinfo(self):
        return os.path.join(self.vault.fileinfo_path, \
                self.store_hash[:2], self.store_hash[2:])
