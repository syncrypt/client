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
from syncrypt.backends import LocalStorageBackend
from syncrypt.managers import UserVaultKeyManager
from syncrypt.models import Bundle, Vault
from tests.base import VaultTestCase


class LocalStorageTestCase(VaultTestCase):
    folder = 'tests/testlocalvault/'

    @asynctest.ignore_loop
    async def test_backend_type(self):
        self.assertEqual(type(self.vault.backend), LocalStorageBackend)

    async def test_upload(self):
        app = self.app
        await app.initialize()
        await app.open_or_init(self.vault)
        backend = self.vault.backend

        await backend.open()

        for bundle in self.vault.walk_disk():
            await bundle.update()
            await backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, True)
            await backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, True)
            await backend.upload(bundle, self.app.identity)
            await backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, False)

    async def test_vault_metadata(self):
        app = self.app
        await app.initialize()
        await app.open_or_init(self.vault)
        backend = self.vault.backend
        await backend.open()

        self.vault.config.vault['name'] = 'My Library'

        await backend.set_vault_metadata()
        await backend.vault_metadata()

        # new connection
        vault2 = Vault(self.vault.folder)
        await vault2.backend.vault_metadata()

    async def test_revision_increase_after_push(self):
        app = SyncryptApp(self.app_config)
        app.add_vault(self.vault)
        await app.initialize()
        await app.open_or_init(self.vault)
        prev_rev = self.vault.revision
        await app.push()
        post_rev = self.vault.revision
        self.assertNotEqual(prev_rev, post_rev)
        self.assertTrue(not post_rev is None)

    async def test_two_local_one_remote(self):
        other_vault_path = os.path.join(VaultTestCase.working_dir, 'othervault')

        # remove "other vault" folder first
        if os.path.exists(other_vault_path):
            shutil.rmtree(other_vault_path)

        app = self.app
        await self.app.initialize()

        app.add_vault(self.vault)

        await app.open_or_init(self.vault)
        await app.push() # init all vaults

        # now we will clone the initialized vault by copying the vault config
        shutil.copytree(os.path.join(self.vault.folder, '.vault'),
                        os.path.join(other_vault_path, '.vault'))
        self.other_vault = Vault(other_vault_path)
        with self.other_vault.config.update_context():
            self.other_vault.config.unset('vault.revision')

        await app.open_or_init(self.other_vault)
        app.add_vault(self.other_vault)

        await app.pull_vault(self.other_vault)

        files_in_new_vault = len(glob(os.path.join(other_vault_path, '*')))
        self.assertEqual(files_in_new_vault, 8)

        keys = UserVaultKeyManager()
        # We have one valid key for both vaults
        self.assertEqual(len(keys.list_for_vault(self.other_vault)), 1)
        self.assertEqual(len(keys.list_for_vault(self.vault)), 1)

        key = keys.list_for_vault(self.vault)[0]
        other_key = keys.list_for_vault(self.other_vault)[0]

        self.assertEqual(key.fingerprint, other_key.fingerprint)
        self.assertNotEqual(key.fingerprint, self.vault.identity.get_fingerprint())
        self.assertEqual(key.fingerprint, self.app.identity.get_fingerprint())
