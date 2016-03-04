import unittest
import os.path
import shutil
import os

import asyncio
import asynctest
from syncrypt import Bundle, Vault
from syncrypt.app import SyncryptApp
from syncrypt.backends import BinaryStorageBackend

from tests.base import VaultTestCase
from tests.common import CommonTestsMixin

__all__ = ('BinaryServerTests',)

class BinaryServerTests(VaultTestCase, CommonTestsMixin):
    folder = 'tests/testbinaryvault/'

    @asynctest.ignore_loop
    def test_backend_type(self):
        self.assertEqual(type(self.vault.backend), BinaryStorageBackend)

if __name__ == '__main__':
    unittest.main()
