import asyncio
import os
import os.path
import shutil
import unittest

import asynctest
from syncrypt.app import SyncryptApp
from syncrypt.app.auth import CredentialsAuthenticationProvider
from syncrypt.backends import BinaryStorageBackend, LocalStorageBackend
from syncrypt.backends.binary import get_manager_instance
from syncrypt.config import AppConfig
from syncrypt.models import Vault
from syncrypt.utils.logging import setup_logging

from syncrypt.models import store


class TestAuthenticationProvider(CredentialsAuthenticationProvider):

    def __init__(self):
        super(TestAuthenticationProvider, self).__init__(
            "test@syncrypt.space", "test!password"
        )


class TestAppConfig(AppConfig):

    def __init__(self, config_file, remote=None):
        super(TestAppConfig, self).__init__(config_file)
        with self.update_context():
            if not remote is None:
                self.update("remote", remote)

            # Change default API port so that tests can be run alongside the daemon
            self.set("api.port", "28081")

            # Store DB is in memory for tests
            self.set("store.path", ":memory:")

            self.set(
                "app.config_dir", os.path.join(os.path.dirname(__file__), "testconfigdir")
            )


class VaultTestCase(asynctest.TestCase):
    folder = None  # type: str
    app_cls = SyncryptApp

    # If available, use filesystem mounted shared memory in order to save
    # disk IO operations during testing
    working_dir = "/dev/shm" if os.access("/dev/shm", os.W_OK) else "tests/"
    vault = None  # type: Vault
    remote = {
            "type": "binary",
            "host": "localhost",
            }

    def setUp(self):
        if self.folder:
            vault_folder = os.path.join(self.working_dir, "testvault")
            if os.path.exists(vault_folder):
                shutil.rmtree(vault_folder)
            shutil.copytree(self.folder, vault_folder)
            self.vault = Vault(vault_folder)

        app_config_file = os.path.join(self.working_dir, "test_config")

        setup_logging("DEBUG")

        if os.path.exists(app_config_file):
            os.remove(app_config_file)

        self.app_config = TestAppConfig(app_config_file, self.remote)

        store.drop(self.app_config)

        self.app = self.app_cls(
            self.app_config, auth_provider=TestAuthenticationProvider()
        )
        asyncio.get_event_loop().run_until_complete(self.app.initialize())

    def tearDown(self):
        asyncio.get_event_loop().run_until_complete(self.app.close())
        asyncio.get_event_loop().run_until_complete(get_manager_instance().close())


class VaultLocalTestCase(VaultTestCase):
    localstoragedir = "/dev/shm/localstorage" if os.access("/dev/shxm", os.W_OK) \
                else os.path.join(os.path.dirname(__file__), "testlocalstorage")
    folder = 'tests/testlocalvault/'
    remote = {
        "type": "local",
        "folder": localstoragedir
    }

    def setUp(self):
        if os.path.exists(self.localstoragedir):
            shutil.rmtree(self.localstoragedir)
        super(VaultLocalTestCase, self).setUp()
