import os.path
import shutil
import unittest

import asyncio
import asynctest
from syncrypt import Bundle, Vault
from syncrypt.backends import LocalStorageBackend
from syncrypt.app import SyncryptApp

from syncrypt.pipes import Once, Buffered, DecryptRSA, EncryptRSA

from tests.base import VaultTestCase
from tests.common import CommonTestsMixin

__all__ = ('LocalStorageTests',)

class LocalStorageTests(VaultTestCase, CommonTestsMixin):
    folder = 'tests/testlocalvault'

    @asynctest.ignore_loop
    def test_backend_type(self):
        self.assertEqual(type(self.vault.backend), LocalStorageBackend)

    @asynctest.ignore_loop
    def test_rsa_pipe(self):
        bundle = self.vault.bundle_for('hello.txt')
        for i in (2, 10, 1242):
            input = b'a' * i + b'b' * int(i / 2)
            pipe = Once(input) \
                >> Buffered(bundle.vault.config.rsa_enc_block_size) \
                >> EncryptRSA(bundle)
            intermediate = yield from pipe.readall()
            pipe = Once(intermediate) \
                >> Buffered(bundle.vault.config.rsa_dec_block_size) \
                >> DecryptRSA(bundle)
            output = yield from pipe.readall()
            self.assertEqual(input, output)

if __name__ == '__main__':
    unittest.main()
