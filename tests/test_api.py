import json
import os
import os.path
import shutil
import time
import unittest
from glob import glob

import aiohttp
import asyncio
import asynctest
import hypothesis.strategies as st
from syncrypt.app import SyncryptApp
from syncrypt.backends import BinaryStorageBackend, LocalStorageBackend
from syncrypt.config import AppConfig
from syncrypt.models import Vault
from tests.base import VaultTestCase


class APITests(VaultTestCase):
    folder = 'tests/testbinaryvault/'

    def _test_app_config(self):
        test_config = AppConfig()
        #test_config = TemporaryAppConfig()
        test_config.set('remote.host', 'localhost')
        return test_config

    def test_api_login(self):
        'try to get a list of files via API'
        app = SyncryptApp(self._test_app_config())
        yield from app.start()
        try:
            login_data = json.dumps({
                'email': 'test@syncrypt.space',
                'password': 'test!password'
            })
            r = yield from aiohttp.post('http://127.0.0.1:28080/v1/auth/login/', data=login_data)
            yield from r.release()

            r = yield from aiohttp.get('http://127.0.0.1:28080/v1/auth/check/')
            c = yield from r.json()
            yield from r.release()
            self.assertEqual(c['connected'], True)

            r = yield from aiohttp.get('http://127.0.0.1:28080/v1/auth/logout/')
            c = yield from r.json()
            yield from r.release()

            r = yield from aiohttp.get('http://127.0.0.1:28080/v1/auth/check/')
            c = yield from r.json()
            yield from r.release()
            self.assertEqual(c['connected'], False)

        finally:
            yield from app.stop()

    def test_api_bundle(self):
        'try to get a list of files via API'
        app = SyncryptApp(self._test_app_config())
        app.add_vault(self.vault)
        yield from app.start()
        try:
            r = yield from aiohttp.get('http://127.0.0.1:28080/v1/vault/')
            c = yield from r.json()
            self.assertEqual(len(c), 1) # only one vault
            yield from r.release()

            vault_uri = c[0]['resource_uri']

            r = yield from aiohttp.get('http://127.0.0.1:28080%s' % vault_uri)
            yield from r.release()

            # get a list of bundles
            bundle_list_uri = 'http://127.0.0.1:28080%sbundle/' % vault_uri

            r = yield from aiohttp.get(bundle_list_uri)
            c = yield from r.json()
            self.assertEqual(len(c), 8)
            #from pprint import pprint; pprint(c)
            yield from r.release()
        finally:
            yield from app.stop()

    def test_app_start_without_vaults(self):
        app = SyncryptApp(self._test_app_config())
        yield from app.start()

        try:

            yield from asyncio.sleep(0.1)

            r = yield from aiohttp.get('http://127.0.0.1:28080/v1/vault/')
            c = yield from r.json()
            self.assertEqual(len(c), 0) # no vault
            yield from r.release()

            r = yield from aiohttp.post('http://127.0.0.1:28080/v1/vault/',
                    data=json.dumps({ 'folder': self.vault.folder }))
            c = yield from r.json()
            self.assertGreater(len(c['resource_uri']), 5)
            yield from r.release()

            teh_vault = c['resource_uri']

            r = yield from aiohttp.get('http://127.0.0.1:28080/v1/vault/')
            c = yield from r.json()
            self.assertEqual(len(c), 1) # one vault
            yield from r.release()

            r = yield from aiohttp.get('http://127.0.0.1:28080' + teh_vault + 'users/')
            c = yield from r.json()

            self.assertEqual(len(c), 1) # one user
            yield from r.release()

            r = yield from aiohttp.delete('http://127.0.0.1:28080' + teh_vault)
            yield from r.release()

            r = yield from aiohttp.get('http://127.0.0.1:28080/v1/vault/')
            c = yield from r.json()
            self.assertEqual(len(c), 0) # no vault
            yield from r.release()

            # TODO actually we need to wait for backend future here
            yield from asyncio.sleep(1.0)

        finally:
            yield from app.stop()

    def test_app_watchdog(self):
        app = SyncryptApp(AppConfig())
        app.add_vault(self.vault)
        yield from app.start()

        try:

            r = yield from aiohttp.get('http://127.0.0.1:28080/v1/vault/')
            c = yield from r.json()
            self.assertEqual(len(c), 1) # only one vault
            yield from r.release()

            r = yield from aiohttp.get('http://127.0.0.1:28080/v1/stats')
            c = yield from r.json()
            self.assertEqual(c['stats']['downloads'], 0)
            self.assertEqual(c['stats']['uploads'], 8)
            self.assertEqual(c['stats']['stats'], 8)
            yield from r.release()

            yield from app.push()

            r = yield from aiohttp.get('http://127.0.0.1:28080/v1/stats')
            c = yield from r.json()
            self.assertEqual(c['stats']['downloads'], 0)
            self.assertEqual(c['stats']['uploads'], 8)
            self.assertEqual(c['stats']['stats'], 16)
            yield from r.release()

            r = yield from aiohttp.get('http://127.0.0.1:28080/v1/config')
            c = yield from r.json()
            self.assertIn('api', c.keys())
            yield from r.release()

        finally:
            yield from app.stop()


