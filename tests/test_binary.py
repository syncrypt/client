import unittest
import os

import asyncio
from syncrypt import Bundle, Vault
from syncrypt.app import SyncryptApp
from syncrypt.backends import BinaryStorageBackend, LocalStorageBackend


class BinaryServerTests(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.close()

    def test_vault(self):
        vault = Vault('tests/testvault2')

        backend = vault.backend

        self.assertEqual(type(backend), BinaryStorageBackend)

        self.assertEqual(len(list(vault.walk())), 3)

    def test_upload(self):
        vault = Vault('tests/testvault2')
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
        vault = Vault('tests/testvault2')
        app = SyncryptApp(vault)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(vault.backend.open())
        loop.run_until_complete(app.sync_all())

    def test_upload(self):
        vault = Vault('tests/testvault2')
        backend = vault.backend

        loop = asyncio.get_event_loop()
        loop.run_until_complete(backend.open())

        for bundle in list(vault.walk()):
            # upload file
            loop.run_until_complete(bundle.update())

            stat = os.stat(bundle.path_crypt)
            crypt_size = stat.st_size

            loop.run_until_complete(backend.upload(bundle))

            # download file
            loop.run_until_complete(backend.download(bundle))

            stat = os.stat(bundle.path_crypt)
            self.assertEqual(stat.st_size, crypt_size)


if __name__ == '__main__':
    unittest.main()
