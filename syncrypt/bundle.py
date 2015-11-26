import hashlib
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

    __slots__ = ('path', 'vault', 'file_hash', 'file_size', 'file_size_crypt',
            'key_size', 'key_size_crypt', 'store_hash')

    def __init__(self, abspath, vault):
        self.vault = vault
        self.path = abspath

        h = hashlib.new(hash_algo)
        h.update(self.relpath.encode(self.vault.config.encoding))
        self.store_hash = h.hexdigest()

    @asyncio.coroutine
    def update(self):
        def update_hash(self):
            logger.info('Hashing %s', self)
            abspath = self.path
            with open(abspath, 'rb') as unencrypted:
                # TODO: dont read whole file into memory but stream it
                original_content = unencrypted.read()
                original_size = len(original_content)

                h = hashlib.new(hash_algo)
                h.update(original_content)
                original_hash = h.hexdigest()
                self.file_hash = original_hash
                self.file_size = original_size

        def update_crypt(self):
            logger.info('Encrypting %s', self)
            abspath = self.path
            with open(abspath, 'rb') as unencrypted:
                # TODO: dont read whole file into memory but stream it
                original_content = unencrypted.read()
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
                with open(self.path_crypt, 'wb') as encrypted_file:
                    enc = aes_engine.encrypt(pad(original_content))
                    encrypted_size = len(enc)
                    encrypted_file.write(enc)

                self.file_size_crypt = encrypted_size
                self.key_size = aes_key_len >> 3
                self.key_size_crypt = len(encrypted_key)

        loop = asyncio.get_event_loop()
        yield from self.update_sem.acquire()
        logger.info('Updating %s', self)
        yield from loop.run_in_executor(None, update_hash, self)
        yield from loop.run_in_executor(None, update_crypt, self)
        self.update_sem.release()

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
