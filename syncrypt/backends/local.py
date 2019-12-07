import logging
import os
import pickle
import shutil
from datetime import datetime
from typing import Any, List, Optional, cast  # pylint: disable=unused-import
from uuid import uuid4

from syncrypt.exceptions import VaultNotInitialized
from syncrypt.models import Bundle, Identity, Revision, RevisionOp, Vault
from syncrypt.pipes import FileReader, FileWriter

from .base import StorageBackend

logger = logging.getLogger(__name__)


def require_vault(f):
    def inner(backend, *args, **kwargs):
        vault = backend.vault
        if vault is None:
            raise ValueError("Invalid argument: No vault")
        return f(backend, *args, **kwargs)
    return inner


def require_revision(f):
    def inner(backend, *args, **kwargs):
        if backend.vault.revision is None:
            raise ValueError("Invalid argument: No revision")
        return f(backend, *args, **kwargs)
    return inner


class LocalStorageBackend(StorageBackend):
    global_auth = None # type: str
    # ^ deprecated

    def __init__(self, vault: Vault = None, folder=None, **kwargs) -> None:
        self.folder = folder
        self.vault = vault

    @property
    def path(self):
        if self.vault is None:
            return self.folder

        if self.vault and not self.vault.config.get("vault.id"):
            raise VaultNotInitialized()

        # folder can be relative to vault
        return os.path.join(
            self.vault.folder, self.folder, self.vault.config.get("vault.id")
        )

    async def open(self):
        if not os.path.isdir(self.path):
            os.makedirs(self.path, exist_ok=True)

    def add_revision(self, revision: Revision) -> Revision:
        "Persist the revision in the local storage. This will also generate a revision id."
        if revision.revision_id is not None:
            raise ValueError("Revision already has an id.")

        if revision.signature is None:
            raise ValueError("Revision is not signed.")

        revision.revision_id = str(uuid4())
        revision.created_at = datetime.utcnow()

        with open(os.path.join(self.path, "txchain"), "ab") as txchain:
            logger.debug(
                "Adding revision %s to signchain (%s)",
                revision.revision_id,
                os.path.join(self.path, "txchain"),
            )
            binary_tx = pickle.dumps(revision)
            txchain.write(binary_tx)

        return revision

    @require_vault
    async def init(self, identity: Identity) -> Revision:
        vault = cast(Vault, self.vault) # We can savely cast because of @require_vault

        new_vault_id = str(uuid4())
        if not vault.config.get("vault.id"):
            with vault.config.update_context():
                vault.config.update("vault", {"id": new_vault_id})

        await self.open()  # create directory

        # create txchain store
        with open(os.path.join(self.path, "txchain"), "wb"):
            pass

        revision = Revision(operation=RevisionOp.CreateVault)
        revision.vault_id = new_vault_id
        revision.user_id = "user@localhost"
        revision.vault_public_key = vault.identity.public_key.exportKey("DER")
        revision.user_public_key = identity.public_key.exportKey("DER")
        revision.sign(identity=identity)

        return self.add_revision(revision)

    async def list_keys(self, user: Optional[str] = None) -> List[Any]:
        return []

    async def list_vaults(self) -> List[Any]:
        return []

    async def list_vaults_for_identity(self, identity: Identity) -> List[Any]:
        return []

    @require_vault
    @require_revision
    async def upload(self, bundle: Bundle, identity: Identity) -> Revision:
        vault = cast(Vault, self.vault) # We can savely cast because of @require_vault

        logger.info("Uploading %s", bundle)
        dest_path = os.path.join(self.path, bundle.store_hash)
        shutil.copyfile(bundle.path, dest_path)

        metadata = await bundle.encrypted_metadata_reader().readall()
        len(metadata)

        if bundle.local_hash is None:
            raise ValueError("Please update bundle before upload.")

        await bundle.load_key()
        s = vault.crypt_engine.read_encrypted_stream(bundle) >> FileWriter(dest_path)
        await s.consume()
        # s = bundle.encrypted_metadata_reader() >> FileWriter(dest_path + ".metadata")
        # await s.consume()
        with open(dest_path + ".hash", "w") as hashfile:
            hashfile.write(bundle.local_hash)

        revision = Revision(operation=RevisionOp.Upload)
        revision.vault_id = vault.config.id
        revision.parent_id = vault.revision
        #revision.user_id = "user@localhost"
        revision.file_hash = bundle.store_hash
        revision.revision_metadata = metadata
        revision.crypt_hash = bundle.local_hash
        revision.file_size_crypt = bundle.file_size_crypt
        revision.sign(identity=identity)

        return self.add_revision(revision)

    @require_vault
    async def download(self, bundle):
        vault = cast(Vault, self.vault) # We can savely cast because of @require_vault

        logger.info("Downloading %s", bundle)

        dest_path = os.path.join(self.path, bundle.store_hash)

        await bundle.load_key()
        stream = FileReader(dest_path)
        try:
            await vault.crypt_engine.write_encrypted_stream(bundle, stream)
        finally:
            await stream.close()

    @require_vault
    @require_revision
    async def set_vault_metadata(self, identity: Identity) -> Revision:
        vault = cast(Vault, self.vault) # We can savely cast because of @require_vault

        dest_path = os.path.join(self.path, "metadata")
        writer = vault.encrypted_metadata_reader() >> FileWriter(
            dest_path, create_dirs=True
        )
        await writer.consume()

        metadata = await vault.encrypted_metadata_reader().readall()

        revision = Revision(operation=RevisionOp.SetMetadata)
        revision.vault_id = vault.config.id
        revision.parent_id = vault.revision
        revision.user_id = "user@localhost"
        revision.revision_metadata = metadata
        revision.sign(identity)

        return self.add_revision(revision)

    async def user_info(self):
        return {
            "email": "user@localhost",
            "first_name": "",
            "last_name": ""
        }

    async def changes(self, since_rev, to_rev):
        logger.info("Reading signchain from %s", os.path.join(self.path, "txchain"))
        with open(os.path.join(self.path, "txchain"), "rb") as txchain:
            try:
                if since_rev:
                    # Skip until since_rev
                    logger.debug("Skipping until %s", since_rev)
                    rev = pickle.load(txchain)
                    while rev.revision_id != since_rev:
                        rev = pickle.load(txchain)

                rev = pickle.load(txchain)
                logger.debug("Loaded %s", rev)

                while rev.revision_id != to_rev:
                    yield rev
                    rev = pickle.load(txchain)
            except EOFError:
                pass
            finally:
                logger.debug("Finished serving changes")

    @require_vault
    @require_revision
    async def remove_file(self, bundle: Bundle, identity: Identity) -> Revision:

        vault = cast(Vault, self.vault) # We can savely cast because of @require_vault

        assert bundle.store_hash

        logger.info("Deleting %s", bundle)

        revision = Revision(operation=RevisionOp.RemoveFile)
        revision.vault_id = vault.config.id
        revision.parent_id = vault.revision
        revision.user_id = "user@localhost"
        revision.file_hash = bundle.store_hash
        revision.sign(identity=identity)

        return self.add_revision(revision)

    def set_auth(self, username: str, password: str):
        pass

    async def upload_identity(self, identity: Identity, description: str=""):
        pass

    @require_vault
    @require_revision
    async def add_vault_user(self, user_id: str, identity: Identity) -> Revision:

        vault = cast(Vault, self.vault) # We can savely cast because of @require_vault

        logger.info("Add user %s", user_id)

        revision = Revision(operation=RevisionOp.AddUser)
        revision.vault_id = vault.config.id
        revision.parent_id = vault.revision
        revision.user_id = user_id
        revision.sign(identity=identity)

        return self.add_revision(revision)

    @require_vault
    @require_revision
    async def remove_vault_user(self, user_id: str, identity: Identity) -> Revision:

        vault = cast(Vault, self.vault) # We can savely cast because of @require_vault

        logger.info("Remove user %s", user_id)

        revision = Revision(operation=RevisionOp.RemoveUser)
        revision.vault_id = vault.config.id
        revision.parent_id = vault.revision
        revision.user_id = user_id
        revision.sign(identity=identity)

        return self.add_revision(revision)

    @require_vault
    @require_revision
    async def add_user_vault_key(self, identity: Identity, user_id: str,
                                 user_identity: Identity, vault_key_package: bytes):

        vault = cast(Vault, self.vault) # We can savely cast because of @require_vault

        logger.info("Add user vault key %s", user_id)

        revision = Revision(operation=RevisionOp.AddUserKey)
        revision.vault_id = vault.config.id
        revision.parent_id = vault.revision
        revision.user_public_key = user_identity.public_key.exportKey('DER')
        revision.user_id = user_id
        revision.sign(identity=identity)

        return self.add_revision(revision)

    @require_vault
    @require_revision
    async def remove_user_vault_key(self, identity: Identity, user_id: str,
                                    user_identity: Identity):

        vault = cast(Vault, self.vault) # We can savely cast because of @require_vault

        logger.info("Removing user vault key %s", user_id)

        revision = Revision(operation=RevisionOp.RemoveUserKey)
        revision.vault_id = vault.config.id
        revision.parent_id = vault.revision
        revision.user_public_key = user_identity.public_key.exportKey('DER')
        revision.user_id = user_id
        revision.sign(identity=identity)

        return self.add_revision(revision)
