import os
import os.path
import shutil
import unittest

import asyncio
import asynctest
from syncrypt import Bundle, Vault
from syncrypt.app import SyncryptApp
from syncrypt.backends import BinaryStorageBackend, LocalStorageBackend


class CommonTestsMixin(object):
    @asynctest.ignore_loop
    def test_vault(self):
        self.assertEqual(len(list(self.vault.walk())), 3)

    @asynctest.ignore_loop
    def test_encrypt(self):
        pass

    def test_upload(self):
        backend = self.vault.backend

        yield from backend.open()

        for bundle in self.vault.walk():
            yield from bundle.encrypt()
            yield from backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, True)
            yield from backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, True)
            yield from backend.upload(bundle)
            yield from backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, False)

    def test_app(self):
        app = SyncryptApp(self.vault)
        yield from self.vault.backend.open()
        yield from app.push()
"""
    def test_upload(self):
        backend = vault.backend

        loop = asyncio.get_event_loop()
        loop.run_until_complete(backend.open())

        for bundle in list(vault.walk()):
            # upload file
            loop.run_until_complete(bundle.encrypt())

            stat = os.stat(bundle.path_crypt)
            crypt_size = stat.st_size

            loop.run_until_complete(backend.upload(bundle))

            # download file
            loop.run_until_complete(backend.download(bundle))

            stat = os.stat(bundle.path_crypt)
            self.assertEqual(stat.st_size, crypt_size)
            """
