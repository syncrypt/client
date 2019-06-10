import os
import os.path
import shutil
import unittest
from glob import glob

import pytest
import trio
import trio_asyncio

from syncrypt.api import APIClient
from syncrypt.app import SyncryptApp, SyncryptDaemonApp
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
def working_dir():
    return "/dev/shm" if os.access("/dev/shm", os.W_OK) else os.path.dirname(__file__)


@pytest.fixture
async def local_app(working_dir):

    app_config_file = os.path.join(working_dir, "test_config")
    if os.path.exists(app_config_file):
        os.remove(app_config_file)
    app_config = TestAppConfig(app_config_file, remote = {
            "type": "local",
            "folder": os.path.join(working_dir, "teststore")
            })
    async with trio.open_nursery() as nursery:
        app = SyncryptApp(app_config, nursery=nursery,
                auth_provider=TestAuthenticationProvider())
        await app.initialize()
        yield app
        await app.close()


@pytest.fixture
async def asyncio_loop():
    # When a ^C happens, trio send a Cancelled exception to each running
    # coroutine. We must protect this one to avoid deadlock if it is cancelled
    # before another coroutine that uses trio-asyncio.
    with trio.CancelScope() as cancel_scope:
        cancel_scope.shield = True
        async with trio_asyncio.open_loop() as loop:
            yield loop


@pytest.fixture
async def local_daemon_app(working_dir, asyncio_loop):
    app_config_file = os.path.join(working_dir, "test_config")
    if os.path.exists(app_config_file):
        os.remove(app_config_file)
    app_config = TestAppConfig(app_config_file, remote = {
            "type": "local",
            "folder": os.path.join(working_dir, "teststore")
            })

    async with trio.open_nursery() as nursery:
        app = SyncryptDaemonApp(app_config, nursery=nursery,
                auth_provider=TestAuthenticationProvider())
        await app.initialize()
        await app.start()
        yield app
        await app.shutdown()


@pytest.fixture
async def local_api_client(local_daemon_app, asyncio_loop):
    client = APIClient(local_daemon_app.config, loop=asyncio_loop)
    yield client
    await client.close()


def assertSameFilesInFolder(self, *folders):
    def all_same(items):
        return all(x == items[0] for x in items)
    files_per_folder = [sorted(os.listdir(folder)) for folder in folders]
    assert all_same([len(files) for files in files_per_folder])
    for fn in zip(*files_per_folder):
        assert all_same(fn)
        assert all_same([os.stat(os.path.join(folder, filename)).st_size for folder, filename in
            zip(folders, fn)])


@pytest.fixture
async def test_vault(working_dir):
    "Return a vault that is a clone of the test vault"

    source_folder = os.path.join('tests', 'testlocalvault/')
    vault_folder = os.path.join(working_dir, "testvault")
    if os.path.exists(vault_folder):
        shutil.rmtree(vault_folder)
    shutil.copytree(source_folder, vault_folder)
    return Vault(vault_folder)


@pytest.fixture
async def empty_vault(working_dir):
    "Return an uninitialized, empty vault"

    vault_folder = os.path.join(working_dir, "testvault")
    if os.path.exists(vault_folder):
        shutil.rmtree(vault_folder)
    os.makedirs(vault_folder)
    return Vault(vault_folder)


@pytest.fixture
async def local_vault(local_app, test_vault):
    "Return a vault that is a clone of the test vault AND is already added to the local app"

    await local_app.add_vault(test_vault)
    yield test_vault


@pytest.fixture
async def local_daemon_vault(local_daemon_app, working_dir, test_vault):
    "Return a vault that is a clone of the test vault AND is already added to the daemon app"

    await local_daemon_app.add_vault(test_vault)
    yield test_vault
