import os
import os.path
import shutil
import unittest

import asyncio
import asynctest
from syncrypt.app import SyncryptApp
from syncrypt.backends import BinaryStorageBackend, LocalStorageBackend
from syncrypt.models import Vault
from syncrypt.config import AppConfig

class TestAppConfig(AppConfig):
    def __init__(self):
        super(TestAppConfig, self).__init__()
        self.set('remote.host', 'localhost')
        self.config_file = os.path.abspath('./test_config')

class VaultTestCase(asynctest.TestCase):
    folder = None

    # If available, use filesystem mounted shared memory in order to save
    # disk IO operations during testing
    working_dir = '/dev/shm' if os.access('/dev/shm', os.W_OK) else 'tests/'

    def setUp(self):
        if self.folder:
            vault_folder = os.path.join(self.working_dir, 'testvault')
            if os.path.exists(vault_folder):
                shutil.rmtree(vault_folder)
            shutil.copytree(self.folder, vault_folder)
            self.vault = Vault(vault_folder)

