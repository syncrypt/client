import pytest
import os
import os.path
import shutil
import unittest
from glob import glob


from syncrypt.app import SyncryptApp
from syncrypt.auth import CredentialsAuthenticationProvider
from syncrypt.backends import BinaryStorageBackend, LocalStorageBackend
from syncrypt.backends.binary import get_manager_instance
from syncrypt.config import AppConfig
from syncrypt.models import Vault, store
from syncrypt.utils.logging import setup_logging


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


@pytest.fixture
async def working_dir(x):
    yield "/dev/shm" if os.access("/dev/shm", os.W_OK) else "tests/"


@pytest.fixture
async def local_app(working_dir):
    print("CREATING APP", working_dir)
    app_config_file = os.path.join(my_working_dir, "test_config")
    app_config = TestAppConfig(app_config_file, remote = {
            "type": "binary",
            "host": "localhost",
            })
    app = SyncryptApp(app_config, auth_provider=TestAuthenticationProvider())
    await app.initialize()
    yield app
    await app.close()


async def generic_vault(folder, app_cls=SyncryptApp, remote = {
            "type": "binary",
            "host": "localhost",
            }):
    app_cls = SyncryptApp

    # If available, use filesystem mounted shared memory in order to save
    # disk IO operations during testing
    vault = None  # type: Vault

    app_config_file = os.path.join(my_working_dir, "test_config")

    setup_logging("DEBUG")

    if os.path.exists(app_config_file):
        os.remove(app_config_file)

    app_config = TestAppConfig(app_config_file, remote)

    store.drop(app_config)

    app = app_cls(app_config, auth_provider=TestAuthenticationProvider())
    await app.initialize()

    yield vault
    
    await app.close()

#    def assertSameFilesInFolder(self, *folders):
#        files_per_folder = [sorted(os.listdir(folder)) for folder in folders]
#        assertEqual(*[len(files) for files in files_per_folder])
#        for fn in zip(*files_per_folder):
#            assertEqual(*fn)
#            assertEqual(*[os.stat(os.path.join(folder, filename)).st_size for folder, filename in
#                zip(folders, fn)])


@pytest.fixture
async def local_vault(local_app, working_dir):
    folder = 'tests/testlocalvault/'
    vault_folder = os.path.join(working_dir, "testvault")
    if os.path.exists(vault_folder):
        shutil.rmtree(vault_folder)
    shutil.copytree(folder, vault_folder)
    vault = Vault(vault_folder)
    await local_app.add_vault(vault)

    yield vault
