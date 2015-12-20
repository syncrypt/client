import hashlib
import logging

from Crypto.Cipher import AES

import aiofiles
import asyncio

logger = logging.getLogger(__name__)

class PKCS5Padding(object):
    @staticmethod
    def pad(s, block_size):
        if len(s) % block_size > 0:
            return s + str.encode((block_size - len(s) % block_size) *
                    chr(block_size - len(s) % block_size))
        else:
            return s

    @staticmethod
    def unpad(s):
        num_pad_chars = s[-1]
        if s[-num_pad_chars:] == s[-1:] * num_pad_chars:
            return s[:-num_pad_chars]
        else:
            return s

class EncryptingStreamReader(object):
    def __init__(self, bundle):
        self.bundle = bundle

    @asyncio.coroutine
    def open(self):
        self.original = yield from aiofiles.open(self.bundle.path, 'rb')
        self.original_hash = hashlib.new(self.bundle.vault.config.hash_algo)
        self.encrypted_hash = hashlib.new(self.bundle.vault.config.hash_algo)
        self.original_size = 0
        self.encrypted_size = 0
        self.aes = AES.new(self.bundle.key, AES.MODE_CBC,
                self.bundle.vault.config.iv)
        self.block_size = self.bundle.vault.config.block_size
        return self

    @asyncio.coroutine
    def close(self):
        yield from self.original.close()

    @asyncio.coroutine
    def read(self, count):
        data = yield from self.original.read(count)
        if len(data) == 0:
            return b''
        self.original_hash.update(data)
        self.original_size += len(data)
        enc_data = self.aes.encrypt(PKCS5Padding.pad(data, self.block_size))
        logger.debug('Encrypted %d bytes -> %d bytes', len(data), len(enc_data))
        self.encrypted_hash.update(enc_data)
        self.encrypted_size += len(enc_data)
        return enc_data

    @asyncio.coroutine
    def consume(self):
        while True:
            if len((yield from self.read(100*1024))) == 0:
                break

class DecryptingStreamWriter(object):
    def __init__(self, bundle):
        self.bundle = bundle

    @asyncio.coroutine
    def open(self):
        self.original = yield from aiofiles.open(self.bundle.path, 'wb')
        self.aes = AES.new(self.bundle.key, AES.MODE_CBC,
                self.bundle.vault.config.iv)
        if self.bundle.key is None:
            yield from self.bundle.load_key()

    @asyncio.coroutine
    def close(self):
        yield from self.original.close()

    @asyncio.coroutine
    def write(self, data):
        logger.debug('Decrypting %d bytes', len(data))
        original_content = self.aes.decrypt(data)
        yield from self.original.write(PKCS5Padding.unpad(original_content))
