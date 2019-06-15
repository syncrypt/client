import json
import os
import os.path
import shutil
import time
import unittest
from glob import glob

import aiohttp
import pytest

import syncrypt
from syncrypt.api import APIClient
from syncrypt.app import SyncryptDaemonApp
from syncrypt.backends import BinaryStorageBackend, LocalStorageBackend
from syncrypt.config import AppConfig
from syncrypt.models import Vault, VaultState
"""
from tests.base import VaultTestCase


@pytest.mark.requires_server
class APITests(VaultTestCase):
    app_cls = SyncryptDaemonApp  # type: ignore
    folder = 'tests/testbinaryvault/'
    login_data = {
        'email': 'test@syncrypt.space',
        'password': 'test!password'
    }

    async def test_api_login(self):
        'try to get a list of files via API'
        app = self.app
        client = APIClient(self.app_config)
        await app.start()
        try:
            r = await client.login(**self.login_data)
            await r.release()
            self.assertEqual(r.status, 200)

            r = await client.get('/v1/auth/check/')
            c = await r.json()
            await r.release()
            self.assertEqual(r.status, 200)
            self.assertEqual(c['connected'], True)

            r = await client.logout()
            c = await r.json()
            self.assertEqual(r.status, 200)
            await r.release()

            r = await client.get('/v1/auth/check/')
            c = await r.json()
            self.assertEqual(r.status, 200)
            await r.release()
            self.assertEqual(c['connected'], False)

        finally:
            await client.close()
            await app.stop()

    async def test_api_bundle(self):
        'try to get a list of files via API'
        app = self.app
        await app.add_vault(self.vault)
        client = APIClient(self.app_config)

        await app.init_vault(self.vault)
        await app.start()

        assert self.vault.state == VaultState.READY

        try:
            r = await client.get('/v1/vault/')
            self.assertEqual(r.status, 200)
            c = await r.json()
            self.assertEqual(len(c), 1) # only one vault
            await r.release()

            vault_uri = c[0]['resource_uri']

            self.assertEqual(c[0]['ignore'], ['.*'])

            r = await client.get(vault_uri)
            await r.release()

            # get a list of bundles
            bundle_list_uri = '%sbundle/' % vault_uri

            r = await client.get(bundle_list_uri)
            c = await r.json()
            self.assertEqual(len(c), 8)
            #from pprint import pprint; pprint(c)
            await r.release()
        finally:
            await client.close()
            await app.stop()

    async def test_api_init_vault(self):
        app = self.app
        client = APIClient(self.app_config)

        new_vault_folder = os.path.join(self.working_dir, 'newvault')
        if os.path.exists(new_vault_folder):
            shutil.rmtree(new_vault_folder)
        os.makedirs(new_vault_folder)

        await app.start()

        try:
            r = await client.login(**self.login_data)
            await r.release()
            self.assertEqual(r.status, 200)

            r = await client.post('/v1/vault/',
                    data=json.dumps({ 'folder': new_vault_folder }))
            c = await r.json()
            self.assertNotEqual(c['resource_uri'], '/v1/vault/None/')
            self.assertGreater(len(c['resource_uri']), 20)
            await r.release()

            vault_uri = c['resource_uri']

            r = await client.get(vault_uri)
            c = await r.json()
            self.assertIn(c['state'], ('uninitialized', 'initializing'))
            await r.release()

            self.assertEqual(len(app.vaults), 1) # one vault
            while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
                await trio.sleep(0.2)
            self.assertEqual(len(app.vaults), 1) # one vault

            r = await client.get('/v1/vault/')
            c = await r.json()
            self.assertEqual(len(c), 1) # one vault
            self.assertEqual(c[0]['state'], 'ready')
            await r.release()

        finally:
            await client.close()
            await app.stop()

    async def test_api_add_user(self):
        app = self.app
        client = APIClient(self.app_config)

        await app.init_vault(self.vault)
        await app.start()

        clone_folder = os.path.join(self.working_dir, 'cloned')
        if os.path.exists(clone_folder):
            shutil.rmtree(clone_folder)

        try:
            r = await client.login(**self.login_data)
            await r.release()
            self.assertEqual(r.status, 200)

            await trio.sleep(0.1)

            r = await client.get('/v1/vault/')
            self.assertEqual(r.status, 200)
            c = await r.json()
            self.assertEqual(len(c), 0) # no vault
            await r.release()

            r = await client.post('/v1/vault/',
                    data=json.dumps({ 'folder': self.vault.folder }))
            c = await r.json()
            self.assertGreater(len(c['resource_uri']), 5)
            await r.release()

            vault_uri = c['resource_uri']

            r = await client.get(vault_uri)
            c = await r.json()
            self.assertIn(c['state'], ('uninitialized', 'initializing', 'syncing'))
            await r.release()

            while app.vaults[0].state in ('uninitialized', 'initializing', 'syncing'):
                await trio.sleep(0.2)

            r = await client.get('/v1/vault/')
            c = await r.json()
            self.assertEqual(len(c), 1) # one vault
            await r.release()

            r = await client.get(vault_uri + 'users/')
            c = await r.json()

            self.assertEqual(len(c), 1) # one user
            await r.release()
            me = c[0]

            # add_user will make sure that the email is added as a user to the vault.
            # it will then return all the keys.
            # For testing purpose, we will add ourselves again

            r = await client.get('/v1/user/' + me['email'] + '/keys/')
            c = await r.json()
            self.assertGreater(len(c), 0) # at least one key
            await r.release()
            fingerprint = c[0]['fingerprint']

            r = await client.post(vault_uri + 'users/',
                data=json.dumps({
                    'email': me['email'],
                    'fingerprints': [fingerprint]
                }))
            c = await r.json()
            await r.release()

            r = await client.get(vault_uri + 'users/' + me['email'] + '/keys/')
            c = await r.json()
            self.assertGreater(len(c), 0) # at least one key
            await r.release()

            r = await client.delete(vault_uri)
            self.assertEqual(r.status, 200)
            await r.release()

            r = await client.get('/v1/vault/')
            c = await r.json()
            self.assertEqual(len(c), 0) # no vault
            await r.release()

            # now lets try to clone the vault

            post_data = json.dumps({
                'folder': clone_folder,
                'id': self.vault.config.id
            })

            r = await client.post('/v1/vault/', data=post_data)
            self.assertEqual(r.status, 200)
            c = await r.json()
            await r.release()

            r = await client.get('/v1/vault/')
            self.assertEqual(r.status, 200)
            c = await r.json()
            await r.release()
            self.assertEqual(len(c), 1)

            self.assertEqual(c[0]['metadata'].get('name'), 'testvault')

            # TODO actually we need to wait for backend future here
            await trio.sleep(1.0)

        finally:
            await client.close()
            await app.stop()

    async def test_api_push(self):
        app = self.app
        client = APIClient(self.app_config)

        await app.add_vault(self.vault)

        await app.init_vault(self.vault)
        await app.start()

        try:

            r = await client.get('/v1/vault/')
            c = await r.json()
            self.assertEqual(len(c), 1) # only one vault
            await r.release()

            r = await client.get('/v1/stats')
            c = await r.json()
            self.assertEqual(c['stats']['downloads'], 0)
            self.assertEqual(c['stats']['uploads'], 8)
            await r.release()

            await app.push()

            r = await client.get('/v1/stats')
            c = await r.json()
            self.assertEqual(c['stats']['downloads'], 0)
            self.assertEqual(c['stats']['uploads'], 8)
            await r.release()

            r = await client.get('/v1/config')
            c = await r.json()
            self.assertIn('api', c.keys())
            await r.release()

            r = await client.get('/v1/vault/')
            c = await r.json()
            self.assertEqual(len(c), 1) # still only one vault
            await r.release()

            self.assertFalse(c[0]['modification_date'] is None)

        finally:
            await client.close()
            await app.stop()

    async def test_api_metadata(self):
        app = self.app
        client = APIClient(self.app_config)

        await app.add_vault(self.vault)

        await app.init_vault(self.vault)
        await app.start()

        try:

            r = await client.get('/v1/vault/')
            self.assertEqual(r.status, 200)
            c = await r.json()
            await r.release()

            self.assertEqual(len(c), 1) # only one vault

            vault_uri = c[0]['resource_uri']

            r = await client.get(vault_uri)
            self.assertEqual(r.status, 200)
            c = await r.json()
            await r.release()

            self.assertEqual(c['metadata'].get('name'), 'testvault')

            patch_data = json.dumps({
                'metadata': dict(c['metadata'], name='newname')
            })
            r = await client.put(vault_uri, data=patch_data)
            self.assertEqual(r.status, 200)
            await r.release()

            r = await client.get(vault_uri)
            self.assertEqual(r.status, 200)
            c = await r.json()
            await r.release()

            self.assertEqual(c['metadata'].get('name'), 'newname')

        finally:
            await client.close()
            await app.stop()

    async def test_api_feedback(self):
        'try to send some feedback over API'
        app = self.app
        client = APIClient(self.app_config)
        await app.start()
        try:
            r = await client.login(**self.login_data)
            await r.release()
            self.assertEqual(r.status, 200)

            r = await client.post('/v1/feedback/', data=json.dumps({
                'feedback_text': 'Hey there fellas!'
            }))
            c = await r.json()
            await r.release()
            self.assertEqual(r.status, 200)

        finally:
            await client.close()
            await app.stop()

    async def test_api_shutdown(self):
        app = self.app
        client = APIClient(self.app_config)
        await app.start()
        try:
            r = await client.get('/v1/version/', params={'check_for_update': 0})
            c = await r.json()
            await r.release()
            self.assertEqual(r.status, 200)

            self.assertEqual(c['installed_version'], syncrypt.__version__)
            self.assertNotIn('update_available', c)

            r = await client.get('/v1/shutdown/')
            c = await r.json()
            await r.release()
            self.assertEqual(r.status, 200)

        finally:
            await client.close()
            await app.wait_for_shutdown()
"""
