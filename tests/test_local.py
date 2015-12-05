import os.path
import shutil
import unittest

import asyncio
import asynctest
from syncrypt import Bundle, Vault
from syncrypt.backends import LocalStorageBackend
from syncrypt.app import SyncryptApp


from base import VaultTestCase
from common import CommonTestsMixin

__all__ = ('LocalStorageTests',)

class LocalStorageTests(VaultTestCase, CommonTestsMixin):
    folder = 'tests/testlocalvault'

    @asynctest.ignore_loop
    def test_backend_type(self):
        self.assertEqual(type(self.vault.backend), LocalStorageBackend)


if __name__ == '__main__':
    unittest.main()
