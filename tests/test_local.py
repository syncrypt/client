import os.path
import shutil
import unittest

import asyncio
from asyncio.test_utils import TestCase
from syncrypt import Bundle, Vault
from syncrypt.backends import LocalStorageBackend
from syncrypt.app import SyncryptApp


class LocalStorageTests(TestCase):
    def setUp(self):
        vault = Vault('tests/testvault1')
        if os.path.isdir(vault.backend.path):
            shutil.rmtree(vault.backend.path)
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.close()

    def test_vault(self):
        vault = Vault('tests/testvault1')
        self.assertEqual(type(vault.backend), LocalStorageBackend)
        self.assertEqual(len(list(vault.walk())), 3)

    def test_upload(self):
        vault = Vault('tests/testvault1')
        backend = vault.backend

        loop = asyncio.get_event_loop()
        loop.run_until_complete(backend.open())

        for bundle in vault.walk():

            loop.run_until_complete(bundle.update())
            loop.run_until_complete(backend.stat(bundle))
            self.assertEqual(bundle.needs_upload(), True)
            loop.run_until_complete(backend.stat(bundle))
            self.assertEqual(bundle.needs_upload(), True)
            loop.run_until_complete(backend.upload(bundle))
            loop.run_until_complete(backend.stat(bundle))
            self.assertEqual(bundle.needs_upload(), False)

    def test_app(self):
        vault = Vault('tests/testvault1')
        app = SyncryptApp(vault)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(vault.backend.open())
        loop.run_until_complete(app.push())

    def test_upload(self):
        vault = Vault('tests/testvault1')
        backend = vault.backend

        loop = asyncio.get_event_loop()
        loop.run_until_complete(backend.open())

        for bundle in vault.walk():
            # upload file
            loop.run_until_complete(bundle.update())
            loop.run_until_complete(backend.upload(bundle))

            # download file
            loop.run_until_complete(backend.download(bundle))

if __name__ == '__main__':
    unittest.main()
