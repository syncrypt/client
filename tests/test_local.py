import logging
from glob import glob
import os
import os.path
import shutil
import unittest

import pytest
import asyncio
import asynctest
from syncrypt.models import Bundle, Vault
from syncrypt.app import SyncryptApp
from syncrypt.backends import LocalStorageBackend
from tests.base import VaultTestCase


class LocalStorageTestCase(VaultTestCase):
    folder = 'tests/testlocalvault/'

    @asynctest.ignore_loop
    async def test_backend_type(self):
        self.assertEqual(type(self.vault.backend), LocalStorageBackend)

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

    async def test_vault_metadata(self):
        app = self.app
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
        await app.open_or_init(self.vault)
        prev_rev = self.vault.revision
        await app.push()
        post_rev = self.vault.revision
        self.assertNotEqual(prev_rev, post_rev)
        self.assertTrue(not post_rev is None)
