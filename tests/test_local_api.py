import json
import os
import os.path
import shutil
from glob import glob

import aiohttp
import pytest
from tests.base import *

from syncrypt.models import VaultState


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
    assert vault_json['metadata']['name'] == 'testvault'


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
    assert len(glob(os.path.join(test_vault.folder, '*.*'))) == 0

    resp = await client.post('/v1/vault/',
            data=json.dumps({ 'folder': test_vault.folder }))
    assert resp['resource_uri'] != '/v1/vault/None/'
    assert len(resp['resource_uri']) > 20

    vault_uri = resp['resource_uri']

    assert len(app.vaults) == 1 # one vault
    while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
        await trio.sleep(0.1)

    resp = await client.get('/v1/vault/')
    assert len(resp) == 1 # one vault
    assert resp[0]['state'] == 'ready'

    c = resp[0] # first vault

    patch_data = json.dumps({
        'metadata': dict(c['metadata'], name='newname')
    })
    await client.put(vault_uri, data=patch_data)

    c = await client.get(vault_uri + 'history/')
    assert len(c['items']) >= 2
    assert c['items'][0]['created_at'] is not None
    assert not c['items'][0]['created_at'].endswith(':')
    assert c['items'][0]['revision_id'] is not None
    assert c['items'][0]['operation'] == "OP_CREATE_VAULT"
    assert c['items'][1]['operation'] == "OP_SET_METADATA"

    with open(os.path.join(test_vault.folder, "test.txt"), "w") as f:
        f.write('hello')

    await app.push()

    c = await client.get(vault_uri + 'history/')
    assert len(c['items']) >= 3
    assert c['items'][-1]['operation'] == "OP_UPLOAD"
    assert c['items'][-1]['path'] == "test.txt"

    await app.sync_vault(app.vaults[0], full=True)

    c = await client.get(vault_uri + 'history/')
    assert len(c['items']) >= 3
    assert c['items'][0]['created_at'] is not None
    assert not c['items'][0]['created_at'].endswith(':')
    assert c['items'][0]['revision_id'] is not None
    assert c['items'][0]['operation'] == "OP_CREATE_VAULT"
    assert c['items'][1]['operation'] == "OP_SET_METADATA"
    assert c['items'][-1]['operation'] == "OP_UPLOAD"
    assert c['items'][-1]['path'] == "test.txt"

    c = await client.get(vault_uri)
    assert c['file_count'] == 1
    assert c['revision_count'] >= 3
    assert c['user_count'] == 1


async def test_api_init_vault_remove_from_sync_and_re_add(local_daemon_app, local_api_client, empty_vault):
    client = local_api_client
    app = local_daemon_app
    test_vault = empty_vault

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
    vault_id = resp[0]['remote_id']

    c = resp[0] # first vault

    await client.delete(vault_uri)
    assert len(app.vaults) == 0 # no vault

    shutil.rmtree(test_vault.folder)
    os.makedirs(test_vault.folder)

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
    assert resp[0]['remote_id'] != vault_id # make sure this is a new vault


async def test_api_init_vault_remove_from_sync_and_re_add_same(local_daemon_app, local_api_client, empty_vault):
    client = local_api_client
    app = local_daemon_app
    test_vault = empty_vault

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
    vault_id = resp[0]['remote_id']

    c = resp[0] # first vault

    await client.delete(vault_uri)
    assert len(app.vaults) == 0 # no vault

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
    assert resp[0]['remote_id'] == vault_id # make sure this is the same vault


async def test_api_init_vault_fingerprints(local_daemon_app, local_api_client, empty_vault):
    app = local_daemon_app
    client = local_api_client

    c = await client.post('/v1/vault/', data=json.dumps({
        'folder': empty_vault.folder
    }))
    assert c['resource_uri'] != '/v1/vault/None/'
    assert len(c['resource_uri']) > 20

    vault_uri = c['resource_uri']

    assert len(app.vaults) == 1 # one vault
    while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
        await trio.sleep(0.2)

    c = await client.get('/v1/vault/')
    assert len(c) == 1 # one vault
    assert c[0]['state'] == 'ready'

    c = c[0] # first vault

    patch_data = json.dumps({
        'metadata': dict(c['metadata'], name='newname')
    })
    c = await client.put(vault_uri, data=patch_data)

    c = await client.get(vault_uri + 'fingerprints/')
    assert len(c) == 1

    await app.sync_vault(app.vaults[0], full=True)

    c = await client.get(vault_uri + 'fingerprints/')
    assert len(c) == 1


async def test_api_watchdog(local_daemon_app, local_api_client, empty_vault):
    client = local_api_client
    app = local_daemon_app
    test_vault = empty_vault

    assert len(app.vaults) == 0
    assert len(glob(os.path.join(test_vault.folder, '*.*'))) == 0

    resp = await client.post('/v1/vault/',
            data=json.dumps({ 'folder': test_vault.folder }))
    assert resp['resource_uri'] != '/v1/vault/None/'
    assert len(resp['resource_uri']) > 20

    vault_uri = resp['resource_uri']

    assert len(app.vaults) == 1 # one vault
    while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
        await trio.sleep(0.1)

    resp = await client.get('/v1/vault/')
    assert len(resp) == 1 # one vault
    assert resp[0]['state'] == 'ready'

    c = resp[0] # first vault

    patch_data = json.dumps({
        'metadata': dict(c['metadata'], name='newname')
    })
    await client.put(vault_uri, data=patch_data)

    c = await client.get(vault_uri + 'history/')
    assert len(c['items']) >= 2
    assert c['items'][0]['created_at'] is not None
    assert not c['items'][0]['created_at'].endswith(':')
    assert c['items'][0]['revision_id'] is not None
    assert c['items'][0]['operation'] == "OP_CREATE_VAULT"
    assert c['items'][1]['operation'] == "OP_SET_METADATA"

    while app.vaults[0].state in (VaultState.UNINITIALIZED, VaultState.SYNCING):
        await trio.sleep(0.1)

    # Create a new file and do five fast-paced changes to it
    for i in range(3):
        with open(os.path.join(test_vault.folder, "test.txt"), "a") as f:
            f.write('hello' + str(i))
        await trio.sleep(0.1)

    # TODO
    await trio.sleep(8.0)

    c = await client.get(vault_uri + 'history/')
    assert len(c['items']) >= 3
    assert c['items'][-1]['operation'] == "OP_UPLOAD"
    assert c['items'][-1]['path'] == "test.txt"
    # Despite multiple changes to test.txt, there should only be one upload
    assert c['items'][-2]['operation'] != "OP_UPLOAD"
