import logging
import os
import os.path
import shutil
import sys
import unittest
from glob import glob

import pytest

from syncrypt.app import SyncryptApp
from syncrypt.backends import LocalStorageBackend
from syncrypt.exceptions import AlreadyPresent, InvalidRevision
from syncrypt.managers import UserVaultKeyManager
from syncrypt.models import Bundle, Identity, Revision, RevisionOp, Vault, store

from .base import assertSameFilesInFolder, local_app, local_vault, test_vault, working_dir


def generate_fake_revision(vault):
    revision = Revision(operation=RevisionOp.SetMetadata)
    revision.vault_id = vault.id
    revision.parent_id = vault.revision
    revision.user_id = "user@localhost"
    revision.user_fingerprint = "aabbcc"
    revision.revision_metadata = b"123456"
    revision.signature = b"12345"
    return revision


async def test_backend_type(local_vault):
    assert type(local_vault.backend) == LocalStorageBackend


@pytest.mark.skipif(sys.platform == 'win32', reason='to have win32 builds')
async def test_upload(local_vault, local_app):
    app = local_app
    await app.initialize()
    await app.open_or_init(local_vault)
    backend = local_vault.backend

    await backend.open()

    async for bundle in app.bundles.upload_bundles_for_vault(local_vault):
        await bundle.update()
        assert bundle.remote_hash_differs == True
        prev_rev_count = local_vault.revision_count
        rev = await backend.upload(bundle, app.identity)
        await app.revisions.apply(rev, local_vault)
        assert local_vault.revision_count == prev_rev_count + 1
        bundle = await app.bundles.get_bundle(local_vault,
                os.path.join(local_vault.folder, bundle.relpath))
        await bundle.update()
        assert bundle.remote_hash_differs == False


async def test_vault_metadata(local_app, local_vault):
    app = local_app
    await app.initialize()
    await app.open_or_init(local_vault)
    backend = local_vault.backend
    await backend.open()

    local_vault.config.vault["name"] = "My Library"

    await backend.set_vault_metadata(app.identity)
    await app.pull()


async def test_revision_increase_after_push(local_app, local_vault):
    app = local_app
    await app.initialize()
    await app.open_or_init(local_vault)
    prev_rev = local_vault.revision
    await app.push()
    post_rev = local_vault.revision
    assert prev_rev != post_rev
    assert not post_rev is None


async def test_two_local_one_remote(local_app, local_vault, working_dir):
    other_vault_path = os.path.join(working_dir, "othervault")

    # remove "other vault" folder first
    if os.path.exists(other_vault_path):
        shutil.rmtree(other_vault_path)

    app = local_app
    await app.initialize()

    await app.open_or_init(local_vault)
    await app.push()  # init all vaults

    # now we will clone the initialized vault by copying the vault config
    shutil.copytree(
        os.path.join(local_vault.folder, ".vault"),
        os.path.join(other_vault_path, ".vault"),
    )
    other_vault = Vault(other_vault_path)
    with other_vault.config.update_context():
        other_vault.config.unset("vault.revision")

    await app.open_or_init(other_vault)
    await app.add_vault(other_vault)

    await app.pull_vault(other_vault)

    files_in_new_vault = len(glob(os.path.join(other_vault_path, "*")))
    assert files_in_new_vault == 8
    assertSameFilesInFolder(local_vault.folder, other_vault_path)

    keys = UserVaultKeyManager(app)
    # We have one valid key for both vaults
    assert len(keys.list_for_vault(other_vault)) == 1
    assert len(keys.list_for_vault(local_vault)) == 1

    key = keys.list_for_vault(local_vault)[0]
    other_key = keys.list_for_vault(other_vault)[0]

    assert key.fingerprint == other_key.fingerprint
    assert key.fingerprint != local_vault.identity.get_fingerprint()
    assert key.fingerprint == app.identity.get_fingerprint()


async def test_local_metadata(local_app, local_vault, working_dir):
    other_vault_path = os.path.join(working_dir, "othervault")

    # remove "other vault" folder first
    if os.path.exists(other_vault_path):
        shutil.rmtree(other_vault_path)

    app = local_app
    await app.initialize()
    await app.open_or_init(local_vault)

    # now we will clone the initialized vault by copying the vault config
    shutil.copytree(
        os.path.join(local_vault.folder, ".vault"),
        os.path.join(other_vault_path, ".vault"),
    )
    other_vault = Vault(other_vault_path)
    with other_vault.config.update_context():
        other_vault.config.unset("vault.revision")

    await app.open_or_init(other_vault)
    await app.add_vault(other_vault)

    await app.pull_vault(other_vault)
    assert other_vault.revision_count > 0

    files_in_new_vault = len(glob(os.path.join(other_vault_path, "*")))
    assert files_in_new_vault == 0

    # Now we change the name of the original vault
    with local_vault.config.update_context():
        other_vault.config.set("vault.name", "abc")

    # Upload metadata with the new name to the server
    revision = await local_vault.backend.set_vault_metadata(app.identity)
    await app.revisions.apply(revision, local_vault)

    original_count = other_vault.revision_count

    # Pull the new vault again to retrieve the change in metadata
    await app.pull_vault(other_vault)

    assert other_vault.revision_count == original_count + 1

    assert local_vault.config.get("vault.name") == other_vault.config.get("vault.name")


async def test_remove_file(local_app, local_vault, working_dir):
    other_vault_path = os.path.join(working_dir, "othervault")

    # remove "other vault" folder first
    if os.path.exists(other_vault_path):
        shutil.rmtree(other_vault_path)

    app = local_app
    await app.initialize()
    await app.open_or_init(local_vault)
    await app.push()  # init all vaults

    pre_rev = local_vault.revision
    await app.remove_file(local_vault, os.path.join(local_vault.folder, "hello.txt"))
    assert pre_rev != local_vault.revision
    await app.remove_file(local_vault, os.path.join(local_vault.folder, "random250k"))
    assert pre_rev != local_vault.revision

    # now we will clone the initialized vault by copying the vault config
    shutil.copytree(
        os.path.join(local_vault.folder, ".vault"),
        os.path.join(other_vault_path, ".vault"),
    )
    other_vault = Vault(other_vault_path)
    with other_vault.config.update_context():
        other_vault.config.unset("vault.revision")

    await app.open_or_init(other_vault)
    await app.add_vault(other_vault)

    await app.pull_vault(other_vault)

    files_in_new_vault = len(glob(os.path.join(other_vault_path, "*")))
    assert files_in_new_vault == 6
    assertSameFilesInFolder(local_vault.folder, other_vault_path)

    keys = UserVaultKeyManager(app)
    # We have one valid key for both vaults
    assert len(keys.list_for_vault(other_vault)) == 1
    assert len(keys.list_for_vault(local_vault)) == 1

    key = keys.list_for_vault(local_vault)[0]
    other_key = keys.list_for_vault(other_vault)[0]

    assert key.fingerprint == other_key.fingerprint
    assert key.fingerprint != local_vault.identity.get_fingerprint()
    assert key.fingerprint == app.identity.get_fingerprint()


async def test_local_fake_revision(local_app, local_vault, working_dir):
    other_vault_path = os.path.join(working_dir, "othervault")
    # remove "other vault" folder first
    if os.path.exists(other_vault_path):
        shutil.rmtree(other_vault_path)
    app = local_app
    await app.initialize()
    await app.open_or_init(local_vault)
    await app.push()

    # add fake revision to local storage
    local_vault.backend.add_revision(generate_fake_revision(local_vault))

    with pytest.raises(InvalidRevision):
        await app.pull_vault(local_vault)


async def test_local_full_pull(local_app, local_vault):
    app = local_app
    await app.initialize()
    await app.open_or_init(local_vault)
    await app.push()
    await app.pull(full=True)
    files_in_vault = len(glob(os.path.join(local_vault.folder, "*")))
    assert files_in_vault == 8


async def test_add_and_remove_user(local_app, local_vault):
    app = local_app
    await app.initialize()
    await app.open_or_init(local_vault)

    await app.add_vault_user(local_vault, 'ericb@localhost')
    await app.add_vault_user(local_vault, 'rakim@localhost')

    users = app.vault_users.list_for_vault(local_vault)
    assert len(users) == 3

    await app.remove_vault_user(local_vault, 'ericb@localhost')

    users = app.vault_users.list_for_vault(local_vault)
    assert len(users) == 2

    await app.pull(full=True) # after a full pull, we should arrive at the same state

    users = app.vault_users.list_for_vault(local_vault)
    assert len(users) == 2


async def test_add_user_with_a_key(local_app, local_vault, working_dir):
    app = local_app
    await app.initialize()
    await app.open_or_init(local_vault)

    # 1. Create ericb identity
    key = os.path.join(working_dir, "ericb_id_rsa")
    key_pub = os.path.join(working_dir, "ericb_id_rsa.pub")

    if os.path.exists(key):
        os.unlink(key)
    if os.path.exists(key_pub):
        os.unlink(key_pub)

    ericb_identity = Identity(key, key_pub, local_app.config)
    await ericb_identity.init()
    await ericb_identity.generate_keys()

    # 2. Add user
    await app.add_vault_user(local_vault, 'ericb@localhost')

    # 3. Add user key
    await app.add_user_vault_key(local_vault, 'ericb@localhost', ericb_identity)

    # 4. Modify metadata with original user
    local_vault.config.vault["name"] = "My Library"

    revision = await local_vault.backend.set_vault_metadata(app.identity)
    await app.revisions.apply(revision, local_vault)

    # 5. Modify metadata with ericb
    local_vault.config.vault["name"] = "Eric's Library"

    revision = await local_vault.backend.set_vault_metadata(ericb_identity)
    await app.revisions.apply(revision, local_vault)

    await app.pull(full=True)

    revisions = app.revisions.list_for_vault(local_vault)
    assert len(revisions) == 7

    user_keys = app.user_vault_keys.list_for_vault(local_vault)
    assert len(user_keys) == 2

    # 6. Remove ericbs key
    await app.remove_user_vault_key(local_vault, 'ericb@localhost', ericb_identity)

    user_keys = app.user_vault_keys.list_for_vault(local_vault)
    assert len(user_keys) == 1

    # 7. Fail while trying to modify metadata with ericb
    local_vault.config.vault["name"] = "Really Eric's Library"

    with pytest.raises(InvalidRevision):
        revision = await local_vault.backend.set_vault_metadata(ericb_identity)
        await app.revisions.apply(revision, local_vault)


async def test_add_user_twice(local_app, local_vault):
    app = local_app
    await app.initialize()
    await app.open_or_init(local_vault)

    users = app.vault_users.list_for_vault(local_vault)
    assert len(users) == 1

    await app.add_vault_user(local_vault, 'ericb@localhost')

    users = app.vault_users.list_for_vault(local_vault)
    assert len(users) == 2

    with pytest.raises(AlreadyPresent):
        await app.add_vault_user(local_vault, 'ericb@localhost')

    users = app.vault_users.list_for_vault(local_vault)
    assert len(users) == 2
