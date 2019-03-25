import asyncio
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
from syncrypt.models import Vault, VaultState
from tests.base import *


login_data = {
    'email': 'test@syncrypt.space',
    'password': 'test!password'
}


async def test_local_daemon_app(local_daemon_app):
    assert len(local_daemon_app.vaults) == 0


async def test_local_daemon_app_version(local_daemon_app, local_api_client):
    client = local_api_client
    r = await client.get('/v1/version/')


async def test_api_login(local_daemon_app, local_api_client):
    'try to get a list of files via API'
    client = local_api_client
    content = await client.get('/v1/auth/check/', raise_for_status=True)
    assert content['connected'] == True


async def test_api_vault(local_daemon_app, local_api_client, local_daemon_vault):
    'try to get a list of files via API'
    client = local_api_client
    assert len(local_daemon_app.vaults) == 1

    content = await client.get('/v1/vault/')
    assert len(content) == 1 # only one vault
    vault_uri = content[0]['resource_uri']
    vault_json = await client.get(vault_uri)
    assert vault_json['resource_uri'] == vault_uri
    assert vault_json['metadata']['name'] == 'My Vault'


async def test_api_metadata(local_daemon_app, local_api_client, local_daemon_vault):
    client = local_api_client

    await local_daemon_app.pull()

    content = await client.get('/v1/vault/')
    assert len(content) == 1 # only one vault

    vault_uri = content[0]['resource_uri']

    c = await client.get(vault_uri)
    assert c['metadata'].get('name') == 'testvault'

    patch_data = json.dumps({
        'metadata': dict(c['metadata'], name='newname')
    })
    content = await client.put(vault_uri, data=patch_data)
    vault_con = await client.get(vault_uri)
    revision_count = vault_con['revision_count']

    assert vault_con['metadata'].get('name') == 'newname'
    assert vault_con['user_count'] == 1
    assert vault_con['file_count'] == 0

    vault_con = await client.put(vault_uri, data=patch_data)
    vault_con = await client.get(vault_uri)

    assert vault_con['metadata'].get('name') == 'newname'
    assert vault_con['user_count'] == 1
    assert vault_con['file_count'] == 0

    # revision count should not change with the repeated patch with same name
    assert vault_con['revision_count'] == revision_count


async def test_api_init_vault_history(local_daemon_app, local_api_client, empty_vault):
    client = local_api_client
    app = local_daemon_app
    test_vault = empty_vault

    assert len(app.vaults) == 0

    resp = await client.post('/v1/vault/',
            data=json.dumps({ 'folder': test_vault.folder }))
    assert resp['resource_uri'] != '/v1/vault/None/'
    assert len(resp['resource_uri']) > 20

    vault_uri = resp['resource_uri']

    assert len(app.vaults) == 1 # one vault
    while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
        await trio.sleep(0.2)

    resp = await client.get('/v1/vault/')
    assert len(resp) == 1 # one vault
    assert resp[0]['state'] == 'ready'

    c = resp[0] # first vault

    patch_data = json.dumps({
        'metadata': dict(c['metadata'], name='newname')
    })
    await client.put(vault_uri, data=patch_data)

    c = await client.get(vault_uri + 'history/')
    assert len(c['items']) == 2
    assert c['items'][0]['created_at'] is not None
    assert not c['items'][0]['created_at'].endswith(':')
    assert c['items'][0]['revision_id'] is not None
    assert c['items'][0]['operation'] == "OP_CREATE_VAULT"
    assert c['items'][1]['operation'] == "OP_SET_METADATA"

    with open(os.path.join(test_vault.folder, "test.txt"), "w") as f:
        f.write('hello')

    await app.push()
    """
    TODO

    c = await client.get(vault_uri + 'history/')
    assert len(c['items']) > 2
    assert c['items'][-1]['operation'] == "OP_UPLOAD"
    assert c['items'][-1]['path'] == "test.txt"

    await app.sync_vault(self.app.vaults[0], full=True)

    r = await client.get(vault_uri + 'history/')
    c = await r.json()
    assert len(c['items']) == 4
    assert c['items'][0]['created_at'] is not None
    assert not c['items'][0]['created_at'].endswith(':')
    assert c['items'][0]['revision_id'] is not None
    assert c['items'][0]['operation'] == "OP_CREATE_VAULT"
    assert c['items'][1]['operation'] == "OP_SET_METADATA"
    assert c['items'][-1]['operation'] == "OP_UPLOAD"
    assert c['items'][-1]['path'] == "test.txt"

    r = await client.get(vault_uri)
    c = await r.json()
    await r.release()
    assert c['file_count'] == 1
    assert c['revision_count'] == 4
    assert c['user_count'] == 1
    """


"""
class APITests():
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
            assert r.status == 200

            r = await client.get('/v1/auth/check/')
            c = await r.json()
            await r.release()
            assert r.status == 200
            assert c['connected'] == True

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
            assert r.status == 200

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

            assert len(app.vaults) == 1 # one vault
            while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
                await asyncio.sleep(0.2)
            assert len(app.vaults) == 1 # one vault

            r = await client.get('/v1/vault/')
            c = await r.json()
            assert len(c) == 1 # one vault
            assert c[0]['state'] == 'ready'
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
            assert r.status == 200
            c = await r.json()
            await r.release()

            assert len(c) == 1 # only one vault

            vault_uri = c[0]['resource_uri']

            r = await client.get(vault_uri)
            assert r.status == 200
            c = await r.json()
            await r.release()

            assert c['metadata'].get('name') == 'testvault'

            patch_data = json.dumps({
                'metadata': dict(c['metadata'], name='newname')
            })
            r = await client.put(vault_uri, data=patch_data)
            assert r.status == 200
            await r.release()

            r = await client.get(vault_uri)
            assert r.status == 200
            c = await r.json()
            await r.release()

            revision_count = c['revision_count']

            assert c['metadata'].get('name') == 'newname'
            assert c['file_count'] == 0
            assert c['user_count'] == 1

            r = await client.put(vault_uri, data=patch_data)
            assert r.status == 200
            await r.release()

            r = await client.get(vault_uri)
            assert r.status == 200
            c = await r.json()
            await r.release()

            assert c['metadata'].get('name') == 'newname'
            # revision count should not change with the repeated patch with same name
            assert c['revision_count'] == revision_count

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
            assert r.status == 200

            r = await client.post('/v1/vault/',
                    data=json.dumps({ 'folder': new_vault_folder }))
            c = await r.json()
            self.assertNotEqual(c['resource_uri'], '/v1/vault/None/')
            self.assertGreater(len(c['resource_uri']), 20)
            await r.release()

            vault_uri = c['resource_uri']

            assert len(app.vaults) == 1 # one vault
            while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
                await asyncio.sleep(0.2)

            r = await client.get('/v1/vault/')
            c = await r.json()
            assert len(c) == 1 # one vault
            assert c[0]['state'] == 'ready'
            await r.release()

            c = c[0] # first vault

            patch_data = json.dumps({
                'metadata': dict(c['metadata'], name='newname')
            })
            r = await client.put(vault_uri, data=patch_data)
            assert r.status == 200
            await r.release()

            r = await client.get(vault_uri + 'history/')
            c = await r.json()
            assert len(c['items']) == 3
            self.assertIsNotNone(c['items'][0]['created_at'])
            self.assertFalse(c['items'][0]['created_at'].endswith(':'))
            self.assertIsNotNone(c['items'][0]['revision_id'])
            assert c['items'][0]['operation'] == "OP_CREATE_VAULT"
            assert c['items'][1]['operation'] == "OP_SET_METADATA"

            with open(os.path.join(new_vault_folder, "test.txt"), "w") as f:
                f.write('hello')

            await self.app.push()

            r = await client.get(vault_uri + 'history/')
            c = await r.json()
            assert len(c['items']) == 4
            assert c['items'][-1]['operation'] == "OP_UPLOAD"
            assert c['items'][-1]['path'] == "test.txt"

            await self.app.sync_vault(self.app.vaults[0], full=True)

            r = await client.get(vault_uri + 'history/')
            c = await r.json()
            assert len(c['items']) == 4
            self.assertIsNotNone(c['items'][0]['created_at'])
            self.assertFalse(c['items'][0]['created_at'].endswith(':'))
            self.assertIsNotNone(c['items'][0]['revision_id'])
            assert c['items'][0]['operation'] == "OP_CREATE_VAULT"
            assert c['items'][1]['operation'] == "OP_SET_METADATA"
            assert c['items'][-1]['operation'] == "OP_UPLOAD"
            assert c['items'][-1]['path'] == "test.txt"

            r = await client.get(vault_uri)
            c = await r.json()
            await r.release()
            assert c['file_count'] == 1
            assert c['revision_count'] == 4
            assert c['user_count'] == 1

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
            assert r.status == 200

            r = await client.post('/v1/vault/',
                    data=json.dumps({ 'folder': new_vault_folder }))
            c = await r.json()
            self.assertNotEqual(c['resource_uri'], '/v1/vault/None/')
            self.assertGreater(len(c['resource_uri']), 20)
            await r.release()

            vault_uri = c['resource_uri']

            assert len(app.vaults) == 1 # one vault
            while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
                await asyncio.sleep(0.2)

            r = await client.get('/v1/vault/')
            c = await r.json()
            assert len(c) == 1 # one vault
            assert c[0]['state'] == 'ready'
            await r.release()

            c = c[0] # first vault

            patch_data = json.dumps({
                'metadata': dict(c['metadata'], name='newname')
            })
            r = await client.put(vault_uri, data=patch_data)
            assert r.status == 200
            await r.release()

            r = await client.get(vault_uri + 'fingerprints/')
            c = await r.json()
            assert len(c) == 1

            await self.app.sync_vault(self.vault, full=True)

            r = await client.get(vault_uri + 'fingerprints/')
            c = await r.json()
            assert len(c) == 1

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
            assert r.status == 200

            r = await client.post('/v1/vault/',
                    data=json.dumps({ 'folder': new_vault_folder }))
            c = await r.json()
            self.assertNotEqual(c['resource_uri'], '/v1/vault/None/')
            self.assertGreater(len(c['resource_uri']), 20)
            await r.release()

            vault_uri = c['resource_uri']

            assert len(app.vaults) == 1 # one vault
            while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
                await asyncio.sleep(0.2)

            r = await client.get('/v1/vault/')
            c = await r.json()
            assert len(c) == 1 # one vault
            assert c[0]['state'] == 'ready'
            await r.release()

            c = c[0] # first vault

            patch_data = json.dumps({
                'metadata': dict(c['metadata'], name='newname')
            })
            r = await client.put(vault_uri, data=patch_data)
            assert r.status == 200
            await r.release()

            r = await client.get(vault_uri + 'users/')
            users = await r.json()
            assert len(users) == 1
            self.assertIsNotNone(users[0]['resource_uri'])
            self.assertIsNotNone(users[0]['email'])

            await self.app.sync_vault(self.vault, full=True)

            r = await client.get(vault_uri + 'users/')
            c = await r.json()
            assert len(users) == 1
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
            assert r.status == 200

            r = await client.post('/v1/vault/',
                    data=json.dumps({ 'folder': new_vault_folder }))
            c = await r.json()
            self.assertNotEqual(c['resource_uri'], '/v1/vault/None/')
            self.assertGreater(len(c['resource_uri']), 20)
            await r.release()

            vault_uri = c['resource_uri']

            assert len(app.vaults) == 1 # one vault
            while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
                await asyncio.sleep(0.2)

            r = await client.get('/v1/vault/')
            c = await r.json()
            assert len(c) == 1 # one vault
            assert c[0]['state'] == 'ready'
            await r.release()

            c = c[0] # first vault

            r = await client.delete(vault_uri)
            assert r.status == 200
            assert len(app.vaults) == 0 # no vault

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

            assert len(app.vaults) == 1 # one vault
            while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
                await asyncio.sleep(0.2)

            r = await client.get('/v1/vault/')
            c = await r.json()
            assert len(c) == 1 # one vault
            assert c[0]['state'] == 'ready'
            await r.release()

        finally:
            await client.close()
            await app.stop()

    async def test_api_vault_ignore_paths(self):
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
            assert r.status == 200

            r = await client.post('/v1/vault/',
                    data=json.dumps({ 'folder': new_vault_folder }))
            c = await r.json()
            self.assertNotEqual(c['resource_uri'], '/v1/vault/None/')
            self.assertGreater(len(c['resource_uri']), 20)
            await r.release()

            vault_uri = c['resource_uri']

            assert len(app.vaults) == 1 # one vault
            while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
                await asyncio.sleep(0.2)

            r = await client.get(vault_uri)
            c = await r.json()
            await r.release()

            assert c['resource_uri'] == vault_uri
            assert c['ignore_paths'] == ['.*']

            patch_data = json.dumps({
                'ignore_paths': ['.*', 'NO-SHARE', 'this_also_not.txt']
            })
            r = await client.put(vault_uri, data=patch_data)
            await r.release()

            r = await client.get(vault_uri)
            c = await r.json()
            await r.release()

            assert c['resource_uri'] == vault_uri
            assert c['ignore_paths'], ['.*', 'NO-SHARE' == 'this_also_not.txt']

        finally:
            await client.close()
            await app.stop()
"""
