import json
import os
import os.path
import shutil
import time
import unittest

import aiohttp
import asyncio
import asynctest
from syncrypt import Bundle, Vault
from syncrypt.app import SyncryptApp
from syncrypt.backends import BinaryStorageBackend, LocalStorageBackend
from syncrypt.config import VaultConfig


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

    def test_app_push1(self):
        app = SyncryptApp(VaultConfig())
        app.add_vault(self.vault)
        yield from app.open_or_init(self.vault)
        bundle = list(self.vault.walk())[0]
        yield from app.push_bundle(bundle)
        yield from app.wait()

    def test_app_start_without_vaults(self):
        app = SyncryptApp(VaultConfig())
        yield from app.start()

        yield from asyncio.sleep(0.1)

        r = yield from aiohttp.get('http://127.0.0.1:28080/v1/vault/')
        c = yield from r.json()
        self.assertEqual(len(c), 0) # no vault
        yield from r.release()

        r = yield from aiohttp.put('http://127.0.0.1:28080/v1/vault/', data=self.vault.folder)
        c = yield from r.json()
        self.assertGreater(len(c['resource_uri']), 5)
        yield from r.release()

        teh_vault = c['resource_uri']

        r = yield from aiohttp.get('http://127.0.0.1:28080/v1/vault/')
        c = yield from r.json()
        self.assertEqual(len(c), 1) # one vault
        yield from r.release()

        r = yield from aiohttp.delete('http://127.0.0.1:28080' + teh_vault)
        yield from r.release()

        r = yield from aiohttp.get('http://127.0.0.1:28080/v1/vault/')
        c = yield from r.json()
        self.assertEqual(len(c), 0) # no vault
        yield from r.release()

        # TODO actually we need to wait for backend future here
        yield from asyncio.sleep(1.0)

        yield from app.stop()

    def test_app_watchdog(self):
        app = SyncryptApp(VaultConfig())
        app.add_vault(self.vault)
        yield from app.start()

        r = yield from aiohttp.get('http://127.0.0.1:28080/v1/vault/')
        c = yield from r.json()
        self.assertEqual(len(c), 1) # only one vault
        yield from r.release()

        r = yield from aiohttp.get('http://127.0.0.1:28080/v1/stats')
        c = yield from r.json()
        self.assertEqual(c['downloads'], 0)
        self.assertEqual(c['uploads'], 8)
        self.assertEqual(c['stats'], 8)
        yield from r.release()

        yield from app.push()

        r = yield from aiohttp.get('http://127.0.0.1:28080/v1/stats')
        c = yield from r.json()
        self.assertEqual(c['downloads'], 0)
        self.assertEqual(c['uploads'], 8)
        self.assertEqual(c['stats'], 16)
        yield from r.release()

        r = yield from aiohttp.get('http://127.0.0.1:28080/v1/config')
        c = yield from r.json()
        self.assertIn('remote', c.keys())
        self.assertIn('api', c.keys())
        yield from r.release()

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