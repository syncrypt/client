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
from syncrypt.crypt.plaintext import PlaintextEngine
from syncrypt.exceptions import InvalidRevision
from syncrypt.managers import UserVaultKeyManager
from syncrypt.models import Bundle, Revision, RevisionOp, Vault
from tests.base import VaultLocalTestCase


class PlaintextTestCase(VaultLocalTestCase):
    folder = 'tests/testplainvault/'

    @asynctest.ignore_loop
    async def test_backend_type(self):
        self.assertEqual(type(self.vault.backend), LocalStorageBackend)
        self.assertEqual(type(self.vault.crypt_engine), PlaintextEngine)

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

        self.vault.config.vault["name"] = "My Library"

        await backend.set_vault_metadata(self.app.identity)
        await app.pull()

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
        other_vault_path = os.path.join(VaultLocalTestCase.working_dir, "othervault")

        # remove "other vault" folder first
        if os.path.exists(other_vault_path):
            shutil.rmtree(other_vault_path)

        app = self.app
        await self.app.initialize()

        app.add_vault(self.vault)

        await app.open_or_init(self.vault)
        await app.push()  # init all vaults

        # now we will clone the initialized vault by copying the vault config
        shutil.copytree(
            os.path.join(self.vault.folder, ".vault"),
            os.path.join(other_vault_path, ".vault"),
        )
        self.other_vault = Vault(other_vault_path)
        with self.other_vault.config.update_context():
            self.other_vault.config.unset("vault.revision")

        await app.open_or_init(self.other_vault)
        app.add_vault(self.other_vault)

        await app.pull_vault(self.other_vault)

        files_in_new_vault = len(glob(os.path.join(other_vault_path, "*")))
        self.assertEqual(files_in_new_vault, 8)
        self.assertSameFilesInFolder(self.vault.folder, other_vault_path)

        keys = UserVaultKeyManager(self.app)
        # We have one valid key for both vaults
        self.assertEqual(len(keys.list_for_vault(self.other_vault)), 1)
        self.assertEqual(len(keys.list_for_vault(self.vault)), 1)

        key = keys.list_for_vault(self.vault)[0]
        other_key = keys.list_for_vault(self.other_vault)[0]

        self.assertEqual(key.fingerprint, other_key.fingerprint)
        self.assertNotEqual(key.fingerprint, self.vault.identity.get_fingerprint())
        self.assertEqual(key.fingerprint, self.app.identity.get_fingerprint())

    async def test_local_metadata(self):
        other_vault_path = os.path.join(VaultLocalTestCase.working_dir, "othervault")

        # remove "other vault" folder first
        if os.path.exists(other_vault_path):
            shutil.rmtree(other_vault_path)

        app = self.app
        await self.app.initialize()

        app.add_vault(self.vault)

        await app.open_or_init(self.vault)

        # now we will clone the initialized vault by copying the vault config
        shutil.copytree(
            os.path.join(self.vault.folder, ".vault"),
            os.path.join(other_vault_path, ".vault"),
        )
        self.other_vault = Vault(other_vault_path)
        with self.other_vault.config.update_context():
            self.other_vault.config.unset("vault.revision")

        await app.open_or_init(self.other_vault)
        app.add_vault(self.other_vault)

        await app.pull_vault(self.other_vault)
        self.assertGreater(self.other_vault.revision_count, 0)

        files_in_new_vault = len(glob(os.path.join(other_vault_path, "*")))
        self.assertEqual(files_in_new_vault, 0)

        # Now we change the name of the original vault
        with self.vault.config.update_context():
            self.other_vault.config.set("vault.name", "abc")

        # Upload metadata with the new name to the server
        revision = await self.vault.backend.set_vault_metadata(self.app.identity)
        await app.revisions.apply(revision, self.vault)

        original_count = self.other_vault.revision_count

        # Pull the new vault again to retrieve the change in metadata
        await app.pull_vault(self.other_vault)

        self.assertEqual(self.other_vault.revision_count, original_count + 1)

        self.assertEqual(
            self.vault.config.get("vault.name"), self.other_vault.config.get("vault.name")
        )

    async def test_delete_file(self):
        other_vault_path = os.path.join(VaultLocalTestCase.working_dir, "othervault")

        # remove "other vault" folder first
        if os.path.exists(other_vault_path):
            shutil.rmtree(other_vault_path)

        app = self.app
        await self.app.initialize()

        app.add_vault(self.vault)

        await app.open_or_init(self.vault)
        await app.push()  # init all vaults

        pre_rev = self.vault.revision
        await app.delete_file(os.path.join(self.vault.folder, "hello.txt"))
        self.assertNotEqual(pre_rev, self.vault.revision)
        await app.delete_file(os.path.join(self.vault.folder, "random250k"))
        self.assertNotEqual(pre_rev, self.vault.revision)

        # now we will clone the initialized vault by copying the vault config
        shutil.copytree(
            os.path.join(self.vault.folder, ".vault"),
            os.path.join(other_vault_path, ".vault"),
        )
        self.other_vault = Vault(other_vault_path)
        with self.other_vault.config.update_context():
            self.other_vault.config.unset("vault.revision")

        await app.open_or_init(self.other_vault)
        app.add_vault(self.other_vault)

        await app.pull_vault(self.other_vault)

        files_in_new_vault = len(glob(os.path.join(other_vault_path, "*")))
        self.assertEqual(files_in_new_vault, 6)
        #self.assertSameFilesInFolder(self.vault.folder, other_vault_path)

        keys = UserVaultKeyManager(self.app)
        # We have one valid key for both vaults
        self.assertEqual(len(keys.list_for_vault(self.other_vault)), 1)
        self.assertEqual(len(keys.list_for_vault(self.vault)), 1)

        key = keys.list_for_vault(self.vault)[0]
        other_key = keys.list_for_vault(self.other_vault)[0]

        self.assertEqual(key.fingerprint, other_key.fingerprint)
        self.assertNotEqual(key.fingerprint, self.vault.identity.get_fingerprint())
        self.assertEqual(key.fingerprint, self.app.identity.get_fingerprint())

    async def test_local_full_pull(self):
        app = self.app
        await self.app.initialize()
        app.add_vault(self.vault)
        await app.open_or_init(self.vault)
        await app.push()
        await app.pull(full=True)
        files_in_vault = len(glob(os.path.join(self.vault.folder, "*")))
        self.assertEqual(files_in_vault, 8)
