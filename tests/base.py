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
from syncrypt.app.auth import CredentialsAuthenticationProvider

class TestAuthenticationProvider(CredentialsAuthenticationProvider):
    def __init__(self):
        super(TestAuthenticationProvider, self).__init__(
            'test@syncrypt.space',
            'test!password'
        )

class TestAppConfig(AppConfig):
    def __init__(self, config_file):
        super(TestAppConfig, self).__init__(config_file)
        with self.update_context():
            self.set('remote.host', 'localhost')

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

        app_config_file = os.path.join(self.working_dir, 'test_config')

        if os.path.exists(app_config_file):
            os.remove(app_config_file)

        self.app_config = TestAppConfig(app_config_file)
        self.app = SyncryptApp(self.app_config, auth_provider=TestAuthenticationProvider())

