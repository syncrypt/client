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
        yield from app.push()

    def test_download(self):
        'for all files -> upload file, delete file, download file'
        backend = self.vault.backend

        yield from backend.open()

        for bundle in list(self.vault.walk()):
            # upload file
            yield from bundle.encrypt()

            stat = os.stat(bundle.path_crypt)
            crypt_size = stat.st_size

            with open(bundle.path, 'rb') as x:
                original_content = x.read()

            yield from backend.upload(bundle)

            # delete file
            os.remove(bundle.path)

            # download file
            yield from backend.download(bundle)


            stat = os.stat(bundle.path_crypt)

            self.assertEqual(stat.st_size, crypt_size)

            yield from bundle.decrypt()

            with open(bundle.path, 'rb') as x:
                current_content = x.read()

            self.assertEqual(original_content, current_content)
