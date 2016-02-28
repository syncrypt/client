import unittest
import os.path
import shutil
import os

import asyncio
import asynctest
from syncrypt import Bundle, Vault
from syncrypt.app import SyncryptApp
from syncrypt.backends import BinaryStorageBackend, LocalStorageBackend

class VaultTestCase(asynctest.TestCase):
    folder = None

    def setUp(self):
        if os.path.exists('tests/testvault'):
            shutil.rmtree('tests/testvault')
        shutil.copytree(self.folder, 'tests/testvault')
        self.vault = Vault('tests/testvault')


