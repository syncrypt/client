import logging
import os
import os.path
import shutil
import unittest

import asyncio
import asynctest
from syncrypt import Bundle, Vault
from syncrypt.app import SyncryptApp
from syncrypt.backends import BinaryStorageBackend
from syncrypt.config import AppConfig
from tests.base import VaultTestCase
from tests.common import CommonTestsMixin

__all__ = ('BinaryServerTests',)

class BinaryServerTests(VaultTestCase, CommonTestsMixin):
    folder = 'tests/testbinaryvault/'

    @asynctest.ignore_loop
    def test_backend_type(self):
        self.assertEqual(type(self.vault.backend), BinaryStorageBackend)

    def test_revision_increase_after_push(self):
        app = SyncryptApp(AppConfig())
        app.add_vault(self.vault)
        prev_rev = self.vault.revision
        yield from app.push()
        post_rev = self.vault.revision
        self.assertNotEqual(prev_rev, post_rev)
        self.assertTrue(not post_rev is None)


if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()

