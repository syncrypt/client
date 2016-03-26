import hashlib
import logging
import os

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5

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

    @property
    def hash_obj(self):
        return self._hash

    @asyncio.coroutine
    def read(self, count=-1):
        data = yield from self.input.read(count)
        if len(data) != 0:
            self._hash.update(data)
            self._size += len(data)
        return data

class Pad(Pipe):
    '''This pipe will just add PKCS5Padding to the stream'''
    def __init__(self, bundle):
        super(Pad, self).__init__()
        self.block_size = bundle.vault.config.block_size

    @asyncio.coroutine
    def read(self, count=-1):
        data = yield from self.input.read(count)
        if len(data) == 0:
            return b''
        return PKCS5Padding.pad(data, self.block_size)

class Encrypt(Pipe):
    def __init__(self, bundle):
        super(Encrypt, self).__init__()
        self.bundle = bundle
        self.aes = None
        self.block_size = self.bundle.vault.config.block_size
        self.iv = None

    @asyncio.coroutine
    def read(self, count=-1):
        data = yield from self.input.read(count)
        if len(data) == 0:
            return b''
        enc_data = b''
        if self.aes is None:
            self.iv = os.urandom(self.block_size)
            self.aes = AES.new(self.bundle.key, AES.MODE_CBC, self.iv)
            logger.debug('Writing IV of %d bytes', len(self.iv))
            enc_data += self.iv
        logger.debug('Encrypting %d bytes -> %d bytes', len(data), len(enc_data))
        enc_data += self.aes.encrypt(PKCS5Padding.pad(data, self.block_size))
        return enc_data

class Decrypt(Pipe):
    def __init__(self, bundle):
        self.bundle = bundle
        self.aes = None
        self.block_size = self.bundle.vault.config.block_size
        super(Decrypt, self).__init__()

    @asyncio.coroutine
    def read(self, count=-1):
        if self.aes is None:
            iv = yield from self.input.read(self.block_size)
            logger.debug('Initializing symmetric decryption: block_size=%d iv=%d',
                    self.block_size, len(iv))
            if self.bundle.key is None:
                yield from self.bundle.load_key()
            self.aes = AES.new(self.bundle.key, AES.MODE_CBC, iv)
        data = yield from self.input.read(count)
        logger.debug('Decrypting %d bytes', len(data))
        original_content = self.aes.decrypt(data)
        return PKCS5Padding.unpad(original_content)

class EncryptRSA(Pipe):
    def __init__(self, bundle):
        super(EncryptRSA, self).__init__()
        self.bundle = bundle

    @asyncio.coroutine
    def read(self, count=-1):
        data = yield from self.input.read(count)
        if len(data) > 0:
            enc_data = PKCS1_v1_5.new(self.bundle.vault.public_key).encrypt(data)
            logger.debug('RSA Encrypted %d -> %d bytes', len(data), len(enc_data))
            return enc_data
        else:
            return data

class DecryptRSA(Pipe):
    def __init__(self, bundle):
        self.bundle = bundle
        super(DecryptRSA, self).__init__()

    @asyncio.coroutine
    def read(self, count=-1):
        data = yield from self.input.read(count)
        if len(data) > 0:
            dec_data = PKCS1_v1_5.new(self.bundle.vault.private_key).decrypt(data, 0)
            logger.debug('RSA Decrypted %d -> %d bytes', len(data), len(dec_data))
            return dec_data
        else:
            return data

