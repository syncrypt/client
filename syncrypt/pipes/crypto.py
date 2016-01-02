import hashlib
import logging

from Crypto.Cipher import AES

import aiofiles
import asyncio

from .base import Pipe
from syncrypt.utils.padding import PKCS5Padding

logger = logging.getLogger(__name__)

class Hash(Pipe):
    'Hash (and count) everything that comes through this pipe'

    def __init__(self, bundle):
        super(Hash, self).__init__()
        self._hash = hashlib.new(bundle.vault.config.hash_algo)
        self._size = 0

    def __str__(self):
        return "<Hash: {0} ({1} bytes)>".format(self.hash, self.size)

    @property
    def size(self):
        return self._size

    @property
    def hash(self):
        return self._hash.hexdigest()

    @asyncio.coroutine
    def read(self, count=-1):
        data = yield from self.input.read(count)
        if len(data) != 0:
            self._hash.update(data)
            self._size += len(data)
        return data

class Encrypt(Pipe):
    def __init__(self, bundle):
        super(Encrypt, self).__init__()
        self.bundle = bundle
        self.aes = AES.new(self.bundle.key, AES.MODE_CBC,
                self.bundle.vault.config.iv)
        self.block_size = self.bundle.vault.config.block_size

    @asyncio.coroutine
    def read(self, count=-1):
        data = yield from self.input.read(count)
        if len(data) == 0:
            return b''
        enc_data = self.aes.encrypt(PKCS5Padding.pad(data, self.block_size))
        logger.debug('Encrypted %d bytes -> %d bytes', len(data), len(enc_data))
        return enc_data

class Decrypt(Pipe):
    def __init__(self, bundle):
        self.bundle = bundle
        self.aes = None
        super(Decrypt, self).__init__()

    @asyncio.coroutine
    def read(self, count=-1):
        if self.aes is None:
            self.aes = AES.new(self.bundle.key, AES.MODE_CBC,
                    self.bundle.vault.config.iv)
            if self.bundle.key is None:
                yield from self.bundle.load_key()
        data = yield from self.input.read(count)
        logger.debug('Decrypting %d bytes', len(data))
        original_content = self.aes.decrypt(data)
        return PKCS5Padding.unpad(original_content)

