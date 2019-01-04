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
from async_timeout import timeout

import syncrypt
from syncrypt.api import APIClient
from syncrypt.app import SyncryptDaemonApp
from syncrypt.models import Vault, VaultState
from tests.base import VaultLocalTestCase


class APIWebsocketTests(VaultLocalTestCase):
    app_cls = SyncryptDaemonApp  # type: ignore
    login_data = {
        'email': 'test@syncrypt.space',
        'password': 'test!password'
    }

    async def test_api_local_websockets_stream(self):
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

            r = await client.get(vault_uri)
            c = await r.json()
            self.assertEqual(c['state'], 'ready')
            await r.release()

            async with client.ws_connect(vault_uri + 'historystream/') as ws:

                self.assertEqual(ws.closed, False)

                try:
                    em = await asyncio.wait_for(ws.receive(), timeout=1.0)
                    #raise Exception(em)
                except asyncio.TimeoutError:
                    pass

                patch_data = json.dumps({
                    'metadata': dict(c['metadata'], name='newname')
                })
                r = await client.put(vault_uri, data=patch_data)
                self.assertEqual(r.status, 200)
                await r.release()

                msg = await asyncio.wait_for(ws.receive(), timeout=2.0)
                self.assertEqual(msg.type, aiohttp.WSMsgType.BINARY)
                rev = json.loads(msg.data.decode('utf-8'))
                self.assertEqual(rev['verified'], True)
                self.assertEqual(rev['operation'], "OP_SET_METADATA")

                await ws.close()

        finally:
            await client.close()
            await app.stop()

