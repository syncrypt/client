import asyncio
import logging
import os
import os.path
import shutil
import unittest
from glob import glob

import asynctest
import pytest

from syncrypt.app import SyncryptApp
from syncrypt.backends import BinaryStorageBackend
from syncrypt.backends.binary import get_manager_instance
from syncrypt.models import Bundle, Vault
from tests.base import VaultTestCase


@pytest.mark.requires_server
class BinaryServerTests(VaultTestCase):
    folder = 'tests/testbinaryvault/'

    @asynctest.ignore_loop
    async def test_backend_type(self):
        self.assertEqual(type(self.vault.backend), BinaryStorageBackend)

    @asynctest.ignore_loop
    async def test_vault(self):
        self.assertEqual(len(list(self.vault.walk_disk())), 8)

    async def test_upload(self):
        app = self.app
        await app.open_or_init(self.vault)
        backend = self.vault.backend

        await backend.open()

        for bundle in self.vault.walk_disk():
            await bundle.update()
            await backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, True)
            await backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, True)
            await backend.upload(bundle)
            await backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, False)

    async def test_upload_2(self):
        app = self.app
        await app.open_or_init(self.vault)
        backend = self.vault.backend

        bundles = list(self.vault.walk_disk())
        files = [b.path for b in bundles]
        keys = {}

        await backend.open()

        for bundle in self.vault.walk_disk():
            await bundle.update()
            keys[bundle.path] = bundle.key
            await backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, True)
            await backend.upload(bundle)
            await backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, False)

        self.vault.clear_bundle_cache()

        for f in files:
            bundle = self.vault.bundle_for(os.path.relpath(f, self.vault.folder))
            await bundle.update()
            self.assertEqual(bundle.key, keys[bundle.path])
            await backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, False)

    async def test_app_push(self):
        await self.app.add_vault(self.vault)
        await self.app.push()

    async def test_app_push1(self):
        app = self.app
        await app.open_or_init(self.vault)
        bundle = list(self.vault.walk_disk())[0]
        await app.push_bundle(bundle)
        await app.wait()

    async def test_vault_metadata(self):
        app = self.app
        await app.open_or_init(self.vault)
        backend = self.vault.backend
        await backend.open()

        self.vault.config.vault['name'] = 'My Library'

        await backend.set_vault_metadata()

    async def test_download(self):
        'for all files -> upload file, delete file, download file'
        app = SyncryptApp(self.app_config)
        await app.open_or_init(self.vault)

        backend = self.vault.backend

        await backend.open()

        bundles = list(self.vault.walk_disk())
        files = [b.path for b in bundles]
        original_contents = {}

        for bundle in bundles:
            # upload file
            await bundle.update()

            with open(bundle.path, 'rb') as x:
                original_contents[bundle.path] = x.read()

            await backend.upload(bundle)

            # delete file
            os.remove(bundle.path)

            # download file
            await backend.download(bundle)

            with open(bundle.path, 'rb') as x:
                current_content = x.read()

            self.assertEqual(original_contents[bundle.path], current_content)

            # delete file
            os.remove(bundle.path)

        # Now we download all files AGAIN, this time by generate a NEW bundle,
        # because we don't want old keys to be present

        self.vault.clear_bundle_cache()

        for f in files:
            bundle = self.vault.bundle_for(os.path.relpath(f, self.vault.folder))

            # download file
            await backend.download(bundle)

            with open(bundle.path, 'rb') as x:
                current_content = x.read()

            self.assertEqual(original_contents[bundle.path], current_content)

    async def test_two_local_one_remote(self):
        other_vault_path = os.path.join(VaultTestCase.working_dir, 'othervault')

        # remove "other vault" folder first
        if os.path.exists(other_vault_path):
            shutil.rmtree(other_vault_path)

        app = self.app
        await app.add_vault(self.vault)

        await app.open_or_init(self.vault)
        await app.push() # init all vaults

        # now we will clone the initialized vault by copying the vault config
        shutil.copytree(os.path.join(self.vault.folder, '.vault'),
                        os.path.join(other_vault_path, '.vault'))
        self.other_vault = Vault(other_vault_path)
        with self.other_vault.config.update_context():
            self.other_vault.config.unset('vault.revision')

        await app.open_or_init(self.other_vault)
        await app.add_vault(self.other_vault)

        await app.pull()

        assert not self.vault.active
        assert not self.other_vault.active

        files_in_new_vault = len(glob(os.path.join(other_vault_path, '*')))
        self.assertEqual(files_in_new_vault, 8)

    async def test_revision_increase_after_push(self):
        app = SyncryptApp(self.app_config)
        await app.add_vault(self.vault)
        await app.open_or_init(self.vault)
        prev_rev = self.vault.revision
        await app.push()
        post_rev = self.vault.revision
        self.assertNotEqual(prev_rev, post_rev)
        self.assertTrue(not post_rev is None)

    async def test_take_only_one_connection(self):
        'this will test if connection slots are properly reused'
        vault = self.vault

        app = SyncryptApp(self.app_config)
        await app.add_vault(vault)
        await app.open_or_init(self.vault)
        await app.pull_vault(vault)
        await app.get_remote_size_for_vault(vault)
        await app.pull_vault(vault)
        await app.get_remote_size_for_vault(vault)
        await app.get_remote_size_for_vault(vault)

        self.assertEqual(get_manager_instance().get_stats()['idle'], 1)


if __name__ == '__main__':
    from syncrypt.utils.logging import setup_logging
    setup_logging(logging.DEBUG)
    unittest.main()
