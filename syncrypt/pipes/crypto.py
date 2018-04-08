import asyncio
import hashlib
import logging
import os

import aiofiles
import Cryptodome.Util
from Cryptodome.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5

from syncrypt.utils.padding import PKCS5Padding

from .base import Buffered, Pipe

logger = logging.getLogger(__name__)


class Hash(Pipe):
    'Hash everything that goes through this pipe'

    def __init__(self, hash_algo):
        super(Hash, self).__init__()
        self._hash = hashlib.new(hash_algo)

    def __str__(self):
        return "<Hash: {0}>".format(self.hash)

    @property
    def hash(self):
        return self._hash.hexdigest()

    @property
    def hash_obj(self):
        return self._hash

    async def read(self, count=-1):
        data = await self.input.read(count)
        if len(data) != 0:
            self._hash.update(data)
        return data


class AESPipe(Pipe):
    # AES has a fixed data block size of 16 bytes
    block_size = 16


class PadAES(AESPipe):
    '''This pipe will add PKCS5Padding to the stream'''

    def __init__(self):
        super(PadAES, self).__init__()
        self.next_block = None

    async def read(self, count=-1):
        if self.next_block is None:
            this_block = await self.input.read(count)
        else:
            if len(self.next_block) == 0:
                return b''
            else:
                this_block = self.next_block

        self.next_block = await self.input.read(count)

        # Only apply padding if last block
        if len(self.next_block) == 0:
            return PKCS5Padding.pad(this_block, self.block_size)
        else:
            return this_block

class UnpadAES(AESPipe):
    '''This pipe will remove PKCS5Padding from the stream'''

    def __init__(self):
        super(UnpadAES, self).__init__()
        self.next_block = None

    async def read(self, count=-1):
        if self.next_block is None:
            this_block = await self.input.read(count)
        else:
            if len(self.next_block) == 0:
                return b''
            else:
                this_block = self.next_block

        self.next_block = await self.input.read(count)

        # Only remove padding if last block
        if len(self.next_block) == 0:
            return PKCS5Padding.unpad(this_block)
        else:
            return this_block

class EncryptAES(AESPipe):
    def __init__(self, key):
        super(EncryptAES, self).__init__()
        self.aes = None
        self.key = key
        self.iv = None

    async def read(self, count=-1):
        data = await self.input.read(count)
        if len(data) == 0:
            return b''
        enc_data = b''
        if self.aes is None:
            self.iv = os.urandom(self.block_size)
            self.aes = AES.new(self.key, AES.MODE_CBC, self.iv)
            logger.debug('Writing IV of %d bytes', len(self.iv))
            enc_data += self.iv
        enc_data += self.aes.encrypt(data)
        logger.debug('Encrypting %d bytes -> %d bytes', len(data), len(enc_data))
        return enc_data

class DecryptAES(AESPipe):
    def __init__(self, key):
        self.aes = None
        self.key = key
        super(DecryptAES, self).__init__()

    async def read(self, count=-1):
        if self.aes is None:
            iv = await self.input.read(self.block_size)
            logger.debug('Initializing symmetric decryption: block=%d iv=%d',
                    self.block_size, len(iv))
            self.aes = AES.new(self.key, AES.MODE_CBC, iv)
        data = await self.input.read(count)
        logger.debug('Decrypting %d bytes', len(data))
        original_content = self.aes.decrypt(data)
        return original_content

class EncryptRSA(Buffered):
    '''
    Asymmetric encryption pipe that divides the incoming stream into blocks
    which will then be encrypted using RSA and PKCS1_v1_5.
    '''
    protocol = PKCS1_v1_5

    def __init__(self, public_key):
        self.public_key = public_key
        self.block_size = self.get_block_size()
        self.cipher = self.protocol.new(self.public_key)
        logger.debug('Encrypting block size: %d bytes', self.block_size)
        super(EncryptRSA, self).__init__(self.block_size)

    def get_block_size(self):
        return Cryptodome.Util.number.size(self.public_key.n) // 8 - 2 * 20 - 2

    async def read(self, count=-1):
        data = await super(EncryptRSA, self).read(-1)
        if len(data) > 0:
            enc_data = self.cipher.encrypt(data)
            logger.debug('RSA Encrypted %d -> %d bytes', len(data), len(enc_data))
            return enc_data
        else:
            return data


class DecryptRSA(Buffered):
    '''
    Asymmetric decryption pipe that decrypts blocks using RSA and will put the
    results together into a stream.
    '''
    protocol = PKCS1_v1_5

    def __init__(self, private_key):
        self.private_key = private_key
        self.block_size = self.get_block_size()
        self.cipher = self.protocol.new(self.private_key)
        logger.debug('Decrypting block size: %d bytes', self.block_size)
        super(DecryptRSA, self).__init__(self.block_size)

    def get_block_size(self):
        return Cryptodome.Util.number.size(self.private_key.n) // 8

    async def read(self, count=-1):
        data = await super(DecryptRSA, self).read(-1)
        if len(data) > 0:
            sentinel = 0
            dec_data = self.cipher.decrypt(data, sentinel)
            logger.debug('RSA Decrypted %d -> %d bytes', len(data), len(dec_data))
            return dec_data
        else:
            return data


class EncryptRSA_PKCS1_OAEP(EncryptRSA):
    '''
    Asymmetric encryption pipe that divides the incoming stream into blocks
    which will then be encrypted using RSA (PKCS1-OAEP protocol).
    '''
    protocol = PKCS1_OAEP


class DecryptRSA_PKCS1_OAEP(DecryptRSA):
    '''
    Asymmetric decryption pipe that decrypts blocks using RSA (PKCS1-OAEP
    protocol) and will put the results together into a stream.
    '''
    protocol = PKCS1_OAEP

    async def read(self, count=-1):
        data = await super(DecryptRSA, self).read(-1)  # pylint: disable=bad-super-call
        if len(data) > 0:
            dec_data = self.cipher.decrypt(data)
            logger.debug('RSA Decrypted %d -> %d bytes', len(data), len(dec_data))
            return dec_data
        else:
            return data
