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
from tests.base import VaultTestCase, TestAppConfig


class APITests(VaultTestCase):
    folder = 'tests/testbinaryvault/'

    def test_api_login(self):
        'try to get a list of files via API'
        app = SyncryptApp(TestAppConfig())
        yield from app.start()
        try:
            login_data = json.dumps({
                'email': 'test@syncrypt.space',
                'password': 'test!password'
            })
            r = yield from aiohttp.post('http://127.0.0.1:28080/v1/auth/login/', data=login_data)
            yield from r.release()
            self.assertEqual(r.status, 200)

            r = yield from aiohttp.get('http://127.0.0.1:28080/v1/auth/check/')
            c = yield from r.json()
            yield from r.release()
            self.assertEqual(r.status, 200)
            self.assertEqual(c['connected'], True)

            r = yield from aiohttp.get('http://127.0.0.1:28080/v1/auth/logout/')
            c = yield from r.json()
            self.assertEqual(r.status, 200)
            yield from r.release()

            r = yield from aiohttp.get('http://127.0.0.1:28080/v1/auth/check/')
            c = yield from r.json()
            self.assertEqual(r.status, 200)
            yield from r.release()
            self.assertEqual(c['connected'], False)

        finally:
            yield from app.stop()

    def test_api_bundle(self):
        'try to get a list of files via API'
        app = SyncryptApp(TestAppConfig())
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

    def test_api_add_user(self):
        app = SyncryptApp(TestAppConfig())
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

            # add_user will make sure that the email is added as a user to the vault.
            # it will then return all the keys.
            # For testing purpose, we will add ourselves again
            me = c[0]['email']
            r = yield from aiohttp.post('http://127.0.0.1:28080' + teh_vault + 'users/',
                data=json.dumps({'email': me}))
            c = yield from r.json()
            yield from r.release()

            r = yield from aiohttp.get('http://127.0.0.1:28080' + teh_vault + 'users/' + me + '/keys/')
            c = yield from r.json()
            self.assertGreater(len(c), 0) # at least one key
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
        app = SyncryptApp(TestAppConfig())
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


