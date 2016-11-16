import os
import os.path
import shutil
import unittest

import aiofiles
import asyncio
import asynctest
from syncrypt.pipes import EncryptRSA, EncryptRSA_PKCS1_OAEP, DecryptRSA, DecryptRSA_PKCS1_OAEP
from syncrypt.pipes import (Buffered, FileReader, Limit, Once, Repeat, Count,
                            SnappyCompress, SnappyDecompress, StreamReader)
from .base import VaultTestCase

class VaultCryptoPipeTests(VaultTestCase):
    folder = 'tests/testbinaryvault/'

    @asynctest.ignore_loop
    def test_rsa_pipe_pkcs1_v15(self):
        bundle = self.vault.bundle_for('hello.txt')
        for i in (2, 10, 1242):
            input = b'a' * i + b'b' * int(i / 2)
            pipe = Once(input) \
                >> EncryptRSA(bundle.vault.identity.public_key)
            intermediate = yield from pipe.readall()
            pipe = Once(intermediate) \
                >> DecryptRSA(bundle.vault.identity.private_key)
            output = yield from pipe.readall()
            self.assertEqual(input, output)

    @asynctest.ignore_loop
    def test_rsa_pipe_pkcs1_oaep(self):
        bundle = self.vault.bundle_for('hello.txt')
        for i in (2, 10, 1242):
            input = b'a' * i + b'b' * int(i / 2)
            pipe = Once(input) \
                >> EncryptRSA_PKCS1_OAEP(bundle.vault.identity.public_key)
            intermediate = yield from pipe.readall()
            pipe = Once(intermediate) \
                >> DecryptRSA_PKCS1_OAEP(bundle.vault.identity.private_key)
            output = yield from pipe.readall()
            self.assertEqual(input, output)