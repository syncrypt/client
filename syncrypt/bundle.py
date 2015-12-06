import hashlib
import aiofiles
import logging
import os

import Crypto.Util.number
import rsa
from Crypto.Cipher import AES

import asyncio

logger = logging.getLogger(__name__)


aes_key_len = 256
rsa_key_len = 1024
hash_algo = 'sha256'
iv = 'This is an IV456'
block_size = 16

pad = lambda s: s + str.encode((block_size - len(s) % block_size) * chr(block_size - len(s) % block_size))

class Bundle(object):
    'A Bundle represents a file with additional information'
    update_sem = asyncio.Semaphore(value=6)

    __slots__ = ('path', 'vault', 'file_size', 'file_size_crypt',
            'key_size', 'key_size_crypt', 'store_hash', 'crypt_hash',
            'remote_crypt_hash', 'uptodate', 'update_handle')

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
        pass

    @asyncio.coroutine
    def encrypt(self):
        'encrypt file (store in .vault)'

        loop = asyncio.get_event_loop()
        yield from self.update_sem.acquire()

        logger.info('Encrypting %s', self)
        unencrypted = yield from aiofiles.open(self.path, 'rb')

        try:
            # TODO: dont read whole file into memory but stream it
            original_content = yield from unencrypted.read()
            original_size = len(original_content)
            aes_key = os.urandom(aes_key_len >> 3)
            aes_engine = AES.new(aes_key, AES.MODE_CBC, iv)

            if not os.path.exists(os.path.dirname(self.path_key)):
                os.makedirs(os.path.dirname(self.path_key))
            with open(self.path_key, 'wb') as encrypted_key_file:
                (encrypted_key, ) = self.vault.public_key.encrypt(aes_key, 0)
                encrypted_key_file.write(encrypted_key)

            if not os.path.exists(os.path.dirname(self.path_crypt)):
                os.makedirs(os.path.dirname(self.path_crypt))

            # build hash on the fly
            h = hashlib.new(hash_algo)

            encrypted_file = yield from aiofiles.open(self.path_crypt, 'wb')
            try:
                h.update(original_content)
                enc = aes_engine.encrypt(pad(original_content))
                encrypted_size = len(enc)
                yield from encrypted_file.write(enc)
            finally:
                yield from encrypted_file.close()
            self.crypt_hash = h.hexdigest()

            self.file_size_crypt = encrypted_size
            self.key_size = aes_key_len >> 3
            self.key_size_crypt = len(encrypted_key)
        finally:
            yield from unencrypted.close()
        self.uptodate = True

        self.update_sem.release()

    def update_and_upload(self):
        def x(bundle):
            yield from bundle.vault.push_bundle(bundle)
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
