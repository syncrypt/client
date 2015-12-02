import os.path
import shutil
import unittest

import asyncio
from asyncio.test_utils import TestCase
from syncrypt import Bundle, Vault
from syncrypt.backends import LocalStorageBackend


class LocalStorageTests(TestCase):
    def setUp(self):
        vault = Vault('tests/testvault1')
        if os.path.isdir(vault.backend.path):
            shutil.rmtree(vault.backend.path)

    def test_vault(self):
        vault = Vault('tests/testvault1')
        self.assertEqual(type(vault.backend), LocalStorageBackend)
        self.assertEqual(len(list(vault.walk())), 3)

    def test_upload(self):
        vault = Vault('tests/testvault1')
        backend = vault.backend

        for bundle in vault.walk():
            loop = asyncio.get_event_loop()
            loop.run_until_complete(backend.open())

            loop.run_until_complete(bundle.update())
            loop.run_until_complete(backend.stat(bundle))
            self.assertEqual(bundle.needs_upload(), True)
            loop.run_until_complete(backend.stat(bundle))
            self.assertEqual(bundle.needs_upload(), True)
            loop.run_until_complete(backend.upload(bundle))
            loop.run_until_complete(backend.stat(bundle))
            self.assertEqual(bundle.needs_upload(), False)

if __name__ == '__main__':
    unittest.main()
