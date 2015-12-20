import hashlib
import logging
import os

import Crypto.Util.number
import rsa
from Crypto.Cipher import AES
from .streams import EncryptingStreamReader, DecryptingStreamWriter

import aiofiles
import asyncio

logger = logging.getLogger(__name__)


aes_key_len = 256
rsa_key_len = 1024
hash_algo = 'sha256'
iv = 'This is an IV456'
block_size = 16

class PKCS5Padding(object):
    @staticmethod
    def pad(s):
        return s + str.encode((block_size - len(s) % block_size) * chr(block_size - len(s) % block_size))

    @staticmethod
    def unpad(s):
        num_pad_chars = s[-1]
        if s[-num_pad_chars:] == s[-1:] * num_pad_chars:
            return s[:-num_pad_chars]
        else:
            return s


class Bundle(object):
    'A Bundle represents a file and some additional information'

    encrypt_semaphore = asyncio.Semaphore(value=8)
    decrypt_semaphore = asyncio.Semaphore(value=8)

    __slots__ = ('path', 'vault', 'file_size', 'file_size_crypt',
            'key_size', 'key_size_crypt', 'store_hash', 'crypt_hash',
            'remote_crypt_hash', 'uptodate', 'update_handle', 'key')

    def __init__(self, abspath, vault):
        self.vault = vault
        self.path = abspath
        self.uptodate = False
        self.remote_crypt_hash = None
        self.update_handle = None

        h = hashlib.new(hash_algo)
        h.update(self.relpath.encode(self.vault.config.encoding))
        self.store_hash = h.hexdigest()

    @property
    def remote_hash_differs(self):
        return self.remote_crypt_hash is None or \
                self.remote_crypt_hash != self.crypt_hash

    @asyncio.coroutine
    def decrypt(self):
        'decrypt file (retrieve from .vault)'
        return

        yield from self.decrypt_semaphore.acquire()
        logger.info('Decrypting %s', self)

        key_file = yield from aiofiles.open(self.path_key, 'rb')
        try:
            encrypted_key = yield from key_file.read()
            aes_key = self.vault.private_key.decrypt(encrypted_key)
            assert len(aes_key) == aes_key_len >> 3
        finally:
            yield from key_file.close()

        decrypting_writer = self.decrypting_writer()
        with (yield from decrypting_writer.open()):
            while True:
                pass

        aes_engine = AES.new(aes_key, AES.MODE_CBC, iv)
        unencrypted = yield from aiofiles.open(self.path, 'wb')
        encrypted = yield from aiofiles.open(self.path_crypt, 'rb')
        try:
            crypt_content = yield from encrypted.read()
            original_content = aes_engine.decrypt(crypt_content)
            yield from unencrypted.write(PKCS5Padding.unpad(original_content))
        finally:
            yield from encrypted.close()
            yield from unencrypted.close()

        self.decrypt_semaphore.release()

    @asyncio.coroutine
    def generate_key(self):
        aes_key = os.urandom(aes_key_len >> 3)
        if not os.path.exists(os.path.dirname(self.path_key)):
            os.makedirs(os.path.dirname(self.path_key))
        with open(self.path_key, 'wb') as encrypted_key_file:
            (encrypted_key, ) = self.vault.public_key.encrypt(aes_key, 0)
            encrypted_key_file.write(encrypted_key)
        self.key = aes_key
        self.key_size = aes_key_len >> 3
        self.key_size_crypt = len(encrypted_key)

    def encrypting_reader(self):
        return EncryptingStreamReader(self)

    def decrypting_writer(self):
        return DecryptingStreamWriter(self)

    @asyncio.coroutine
    def encrypt(self):
        'encrypt file (store in .vault)'

        yield from self.encrypt_semaphore.acquire()
        logger.info('Encrypting %s', self)

        yield from self.generate_key()

        reader = self.encrypting_reader()

        try:
            yield from reader.open()
            yield from reader.consume()
        finally:
            yield from reader.close()

        self.crypt_hash = reader.encrypted_hash.digest().hex()
        self.file_size_crypt = reader.encrypted_size
        self.uptodate = True
        self.encrypt_semaphore.release()

    def update_and_upload(self):
        backend = self.vault.backend
        def x(bundle):
            yield from bundle.encrypt()
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
    def path_crypt(self):
        return os.path.join(self.vault.crypt_path, \
                self.store_hash[:2], self.store_hash)

    @property
    def path_key(self):
        return os.path.join(self.vault.keys_path, \
                self.store_hash[:2], self.store_hash)
