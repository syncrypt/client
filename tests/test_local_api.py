import json
import os
import os.path
import shutil
import time
import unittest
from glob import glob

import pytest
import aiohttp
import asyncio
import asynctest
import hypothesis.strategies as st
from syncrypt.backends import BinaryStorageBackend, LocalStorageBackend
from syncrypt.config import AppConfig
from syncrypt.models import Vault, VaultState
from syncrypt.app import SyncryptDaemonApp
from tests.base import VaultTestCase

from syncrypt.api import APIClient
import syncrypt

class APITests(VaultTestCase):
    app_cls = SyncryptDaemonApp  # type: ignore
    folder = 'tests/testlocalvault/'
    remote = {
        "type": "local",
        "folder": "/tmp",
    }
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
    """
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
    """
