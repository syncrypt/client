import hashlib
import logging

from Crypto.Cipher import AES

import aiofiles
import asyncio

logger = logging.getLogger(__name__)

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
