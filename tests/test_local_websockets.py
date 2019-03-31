import json
import os
import os.path
import shutil
from glob import glob

import aiohttp
import pytest
from tests.base import *

from trio_websocket import open_websocket_url
from syncrypt.models import VaultState


async def test_api_local_websockets_stream(local_daemon_app, empty_vault, local_api_client):
    app = local_daemon_app
    client = local_api_client

    c = await client.post('/v1/vault/',
            data=json.dumps({ 'folder': empty_vault.folder }))
    assert c['resource_uri'] != '/v1/vault/None/'
    assert len(c['resource_uri']) > 20

    vault_uri = c['resource_uri']

    assert len(app.vaults) == 1 # one vault
    while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
        await trio.sleep(0.2)
    assert len(app.vaults) == 1 # one vault

    c = await client.get(vault_uri)
    assert c['state'] == 'ready'

    ws_url = "ws://127.0.0.1:28081" + vault_uri + "historystream/"
    async with open_websocket_url(ws_url) as ws:
        assert not ws.closed
        assert ws.is_client

        with trio.move_on_after(0.5):
            message = await ws.get_message()
            assert False, "should not receive a message"

        patch_data = json.dumps({
            'metadata': dict(c['metadata'], name='newname')
        })
        c = await client.put(vault_uri, data=patch_data)

        msg = None
        with trio.move_on_after(0.5):
            msg = await ws.get_message()

        assert msg is not None
        rev = json.loads(msg)
        assert rev['verified'] == True
        assert rev['operation'] == "OP_SET_METADATA"


async def test_api_local_websockets_resync(
        local_daemon_app, empty_vault, local_api_client
    ):
    app = local_daemon_app
    client = local_api_client

    c = await client.post('/v1/vault/',
            data=json.dumps({ 'folder': empty_vault.folder }))
    assert c['resource_uri'] != '/v1/vault/None/'
    assert len(c['resource_uri']) > 20

    vault_uri = c['resource_uri']

    assert len(app.vaults) == 1 # one vault
    while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
        await trio.sleep(0.2)
    assert len(app.vaults) == 1 # one vault

    c = await client.get(vault_uri)
    assert c['state'] == 'ready'

    ws_url = "ws://127.0.0.1:28081" + vault_uri + "historystream/"
    async with open_websocket_url(ws_url) as ws:
        assert not ws.closed
        assert ws.is_client

        with trio.move_on_after(0.5):
            message = await ws.get_message()
            assert False, "should not receive a message"

        c = await client.get(vault_uri + 'resync/')

        msg = None
        with trio.move_on_after(0.5):
            msg = await ws.get_message()

        assert msg is not None
        rev = json.loads(msg)
        assert rev['verified'] == True
        assert rev['operation'] == "OP_CREATE_VAULT"
