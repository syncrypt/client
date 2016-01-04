import os
import os.path
import shutil
import unittest

import asyncio
import asynctest
from syncrypt import Bundle, Vault
from syncrypt.app import SyncryptApp
from syncrypt.config import VaultConfig
from syncrypt.backends import BinaryStorageBackend, LocalStorageBackend


class CommonTestsMixin(object):
    @asynctest.ignore_loop
    def test_vault(self):
        self.assertEqual(len(list(self.vault.walk())), 8)

    @asynctest.ignore_loop
    def test_encrypt(self):
        pass

    def test_upload(self):
        backend = self.vault.backend

        yield from backend.open()

        for bundle in self.vault.walk():
            yield from bundle.update()
            yield from backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, True)
            yield from backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, True)
            yield from backend.upload(bundle)
            yield from backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, False)

    def test_upload_2(self):
        backend = self.vault.backend

        bundles = list(self.vault.walk())
        files = [b.path for b in bundles]
        keys = {}

        yield from backend.open()

        for bundle in self.vault.walk():
            yield from bundle.update()
            keys[bundle.path] = bundle.key
            yield from backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, True)
            yield from backend.upload(bundle)
            yield from backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, False)

        self.vault.clear_bundle_cache()

        for f in files:
            bundle = self.vault.bundle_for(os.path.relpath(f, self.vault.folder))
            yield from bundle.update()
            self.assertEqual(bundle.key, keys[bundle.path])
            yield from backend.stat(bundle)
            self.assertEqual(bundle.remote_hash_differs, False)

    def test_app_push(self):
        app = SyncryptApp(VaultConfig())
        app.add_vault(self.vault)
        yield from app.push()

    def test_app_watchdog(self):
        app = SyncryptApp(VaultConfig())
        app.add_vault(self.vault)
        yield from app.start()

        yield from app.stop()

    def test_download(self):
        'for all files -> upload file, delete file, download file'
        backend = self.vault.backend

        yield from backend.open()

        bundles = list(self.vault.walk())
        files = [b.path for b in bundles]
        original_contents = {}

        for bundle in bundles:
            # upload file
            yield from bundle.update()

            with open(bundle.path, 'rb') as x:
                original_contents[bundle.path] = x.read()

            yield from backend.upload(bundle)

            # delete file
            os.remove(bundle.path)

            # download file
            yield from backend.download(bundle)

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
            yield from backend.download(bundle)

            with open(bundle.path, 'rb') as x:
                current_content = x.read()

            self.assertEqual(original_contents[bundle.path], current_content)
