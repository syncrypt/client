import logging
import os.path
import shutil
import unittest

import asyncio
import asynctest
from syncrypt import Bundle, Vault
from syncrypt.app import SyncryptApp
from syncrypt.backends import LocalStorageBackend
from syncrypt.pipes import (Buffered, DecryptRSA, DecryptRSA_PKCS1_OAEP,
                            EncryptRSA, EncryptRSA_PKCS1_OAEP, Once)
from tests.base import VaultTestCase
from tests.common import CommonTestsMixin

__all__ = ('LocalStorageTests',)

class LocalStorageTests(VaultTestCase, CommonTestsMixin):
    folder = 'tests/testlocalvault'

    @asynctest.ignore_loop
    def test_backend_type(self):
        self.assertEqual(type(self.vault.backend), LocalStorageBackend)

    @asynctest.ignore_loop
    def test_rsa_pipe_pkcs1_v15(self):
        bundle = self.vault.bundle_for('hello.txt')
        for i in (2, 10, 1242):
            input = b'a' * i + b'b' * int(i / 2)
            pipe = Once(input) \
                >> EncryptRSA(bundle.vault.public_key)
            intermediate = yield from pipe.readall()
            pipe = Once(intermediate) \
                >> DecryptRSA(bundle.vault.private_key)
            output = yield from pipe.readall()
            self.assertEqual(input, output)

    @asynctest.ignore_loop
    def test_rsa_pipe_pkcs1_oaep(self):
        bundle = self.vault.bundle_for('hello.txt')
        for i in (2, 10, 1242):
            input = b'a' * i + b'b' * int(i / 2)
            pipe = Once(input) \
                >> EncryptRSA_PKCS1_OAEP(bundle.vault.public_key)
            intermediate = yield from pipe.readall()
            pipe = Once(intermediate) \
                >> DecryptRSA_PKCS1_OAEP(bundle.vault.private_key)
            output = yield from pipe.readall()
            self.assertEqual(input, output)

if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()

