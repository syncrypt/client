import hashlib
import logging

from Crypto.Cipher import AES

import aiofiles
import asyncio

logger = logging.getLogger(__name__)

# todo: move to config
hash_algo = 'sha256'
iv = 'This is an IV456'
block_size = 16

aes_key_len = 256
rsa_key_len = 1024

class PKCS5Padding(object):
    @staticmethod
    def pad(s):
        return s + str.encode((block_size - len(s) % block_size) *
                chr(block_size - len(s) % block_size))

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
        self.original_hash = hashlib.new(hash_algo)
        self.encrypted_hash = hashlib.new(hash_algo)
        self.original_size = 0
        self.encrypted_size = 0
        self.aes = AES.new(self.bundle.key, AES.MODE_CBC, iv)
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
        logger.debug('Encrypting %d bytes', len(data))
        enc_data = self.aes.encrypt(PKCS5Padding.pad(data))
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
        self.aes = AES.new(self.bundle.key, AES.MODE_CBC, iv)

    @asyncio.coroutine
    def close(self):
        yield from self.original.close()

    @asyncio.coroutine
    def write(self, data):
        logger.debug('Decrypting %d bytes', len(data))
        original_content = self.aes.decrypt(data)
        yield from self.original.write(PKCS5Padding.unpad(original_content))
