import asyncio
import json
import os
import os.path
import shutil
import time
import unittest
from glob import glob

import aiohttp
import asynctest
import pytest

import syncrypt
from syncrypt.api import APIClient
from syncrypt.app import SyncryptDaemonApp
from syncrypt.models import Vault, VaultState
from tests.base import VaultLocalTestCase


class APITests(VaultLocalTestCase):
    app_cls = SyncryptDaemonApp  # type: ignore
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
                await asyncio.sleep(0.2)
            self.assertEqual(len(app.vaults), 1) # one vault

            r = await client.get('/v1/vault/')
            c = await r.json()
            self.assertEqual(len(c), 1) # one vault
            self.assertEqual(c[0]['state'], 'ready')
            await r.release()

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

            revision_count = c['revision_count']

            self.assertEqual(c['metadata'].get('name'), 'newname')

            r = await client.put(vault_uri, data=patch_data)
            self.assertEqual(r.status, 200)
            await r.release()

            r = await client.get(vault_uri)
            self.assertEqual(r.status, 200)
            c = await r.json()
            await r.release()

            self.assertEqual(c['metadata'].get('name'), 'newname')
            # revision count should not change with the repeated patch with same name
            self.assertEqual(c['revision_count'], revision_count)

        finally:
            await client.close()
            await app.stop()

    async def test_api_init_vault_history(self):
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

            self.assertEqual(len(app.vaults), 1) # one vault
            while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
                await asyncio.sleep(0.2)

            r = await client.get('/v1/vault/')
            c = await r.json()
            self.assertEqual(len(c), 1) # one vault
            self.assertEqual(c[0]['state'], 'ready')
            await r.release()

            c = c[0] # first vault

            patch_data = json.dumps({
                'metadata': dict(c['metadata'], name='newname')
            })
            r = await client.put(vault_uri, data=patch_data)
            self.assertEqual(r.status, 200)
            await r.release()

            r = await client.get(vault_uri + 'history/')
            c = await r.json()
            self.assertEqual(len(c['items']), 3)
            self.assertIsNotNone(c['items'][0]['created_at'])
            self.assertFalse(c['items'][0]['created_at'].endswith(':'))
            self.assertIsNotNone(c['items'][0]['revision_id'])
            self.assertIsNotNone(c['items'][0]['operation'])

            await self.app.sync_vault(self.vault, full=True)

            r = await client.get(vault_uri + 'history/')
            c = await r.json()
            self.assertEqual(len(c['items']), 3)
            self.assertIsNotNone(c['items'][0]['created_at'])
            self.assertFalse(c['items'][0]['created_at'].endswith(':'))
            self.assertIsNotNone(c['items'][0]['revision_id'])
            self.assertIsNotNone(c['items'][0]['operation'])

        finally:
            await client.close()
            await app.stop()

    async def test_api_init_vault_fingerprints(self):
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

            self.assertEqual(len(app.vaults), 1) # one vault
            while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
                await asyncio.sleep(0.2)

            r = await client.get('/v1/vault/')
            c = await r.json()
            self.assertEqual(len(c), 1) # one vault
            self.assertEqual(c[0]['state'], 'ready')
            await r.release()

            c = c[0] # first vault

            patch_data = json.dumps({
                'metadata': dict(c['metadata'], name='newname')
            })
            r = await client.put(vault_uri, data=patch_data)
            self.assertEqual(r.status, 200)
            await r.release()

            r = await client.get(vault_uri + 'fingerprints/')
            c = await r.json()
            self.assertEqual(len(c), 1)

            await self.app.sync_vault(self.vault, full=True)

            r = await client.get(vault_uri + 'fingerprints/')
            c = await r.json()
            self.assertEqual(len(c), 1)

        finally:
            await client.close()
            await app.stop()

    async def test_api_init_vault_users(self):
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

            self.assertEqual(len(app.vaults), 1) # one vault
            while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
                await asyncio.sleep(0.2)

            r = await client.get('/v1/vault/')
            c = await r.json()
            self.assertEqual(len(c), 1) # one vault
            self.assertEqual(c[0]['state'], 'ready')
            await r.release()

            c = c[0] # first vault

            patch_data = json.dumps({
                'metadata': dict(c['metadata'], name='newname')
            })
            r = await client.put(vault_uri, data=patch_data)
            self.assertEqual(r.status, 200)
            await r.release()

            r = await client.get(vault_uri + 'users/')
            users = await r.json()
            self.assertEqual(len(users), 1)
            self.assertIsNotNone(users[0]['resource_uri'])
            self.assertIsNotNone(users[0]['email'])

            await self.app.sync_vault(self.vault, full=True)

            r = await client.get(vault_uri + 'users/')
            c = await r.json()
            self.assertEqual(len(users), 1)
            self.assertIsNotNone(users[0]['resource_uri'])
            self.assertIsNotNone(users[0]['email'])

        finally:
            await client.close()
            await app.stop()

    async def test_api_init_vault_remove_from_sync_and_re_add(self):
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

            self.assertEqual(len(app.vaults), 1) # one vault
            while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
                await asyncio.sleep(0.2)

            r = await client.get('/v1/vault/')
            c = await r.json()
            self.assertEqual(len(c), 1) # one vault
            self.assertEqual(c[0]['state'], 'ready')
            await r.release()

            c = c[0] # first vault

            r = await client.delete(vault_uri)
            self.assertEqual(r.status, 200)
            self.assertEqual(len(app.vaults), 0) # no vault

            shutil.rmtree(new_vault_folder)
            os.makedirs(new_vault_folder)

            # lets re-add the same vault in this directory
            r = await client.post('/v1/vault/',
                    data=json.dumps({ 'folder': new_vault_folder }))
            c = await r.json()
            self.assertNotEqual(c['resource_uri'], '/v1/vault/None/')
            self.assertGreater(len(c['resource_uri']), 20)
            await r.release()

            vault_uri = c['resource_uri']

            self.assertEqual(len(app.vaults), 1) # one vault
            while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
                await asyncio.sleep(0.2)

            r = await client.get('/v1/vault/')
            c = await r.json()
            self.assertEqual(len(c), 1) # one vault
            self.assertEqual(c[0]['state'], 'ready')
            await r.release()

        finally:
            await client.close()
            await app.stop()
