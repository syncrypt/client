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
    working_dir = '/dev/shm' if os.access('/dev/shm', os.W_OK) else 'tests/'

    def setUp(self):
        vault_folder = os.path.join(self.working_dir, 'testvault')
        if os.path.exists(vault_folder):
            shutil.rmtree(vault_folder)
        shutil.copytree(self.folder, vault_folder)
        self.vault = Vault(vault_folder)


