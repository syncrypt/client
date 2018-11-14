import asyncio
import logging
import os
import pickle
import shutil
from typing import Any, cast  # pylint: disable=unused-import
from uuid import uuid4

from syncrypt.exceptions import VaultNotInitialized
from syncrypt.models import Bundle, Identity, Revision, RevisionOp, Vault
from syncrypt.pipes import FileReader, FileWriter

from .base import RevisionQueue, StorageBackend

logger = logging.getLogger(__name__)


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

    async def init(self, identity: Identity) -> Revision:
        vault = self.vault
        if vault is None:
            raise ValueError("Invalid argument")

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

    async def upload(self, bundle: Bundle, identity: Identity) -> Revision:
        vault = self.vault
        if vault is None:
            raise ValueError("Invalid argument")

        assert vault.revision is not None

        logger.info("Uploading %s", bundle)
        dest_path = os.path.join(self.path, bundle.store_hash)
        shutil.copyfile(bundle.path, dest_path)

        metadata = await bundle.encrypted_metadata_reader().readall()
        len(metadata)

        await bundle.load_key()
        s = vault.crypt_engine.read_encrypted_stream(bundle) >> FileWriter(dest_path)
        await s.consume()
        # s = bundle.encrypted_metadata_reader() >> FileWriter(dest_path + ".metadata")
        # await s.consume()
        with open(dest_path + ".hash", "w") as hashfile:
            hashfile.write(bundle.crypt_hash)

        revision = Revision(operation=RevisionOp.Upload)
        revision.vault_id = vault.config.id
        revision.parent_id = vault.revision
        #revision.user_id = "user@localhost"
        revision.file_hash = bundle.store_hash
        revision.revision_metadata = metadata
        revision.crypt_hash = bundle.crypt_hash
        revision.file_size_crypt = bundle.file_size_crypt
        revision.sign(identity=identity)

        return self.add_revision(revision)

    def add_revision(self, revision: Revision) -> Revision:
        "Persist the revision in the local storage. This will also generate a revision id."
        if revision.revision_id is not None:
            raise ValueError("Revision already has an id.")

        if revision.signature is None:
            raise ValueError("Revision is not signed.")

        revision.revision_id = str(uuid4())

        with open(os.path.join(self.path, "txchain"), "ab") as txchain:
            logger.debug(
                "Adding revision %s to signchain (%s)",
                revision.revision_id,
                os.path.join(self.path, "txchain"),
            )
            binary_tx = pickle.dumps(revision)
            txchain.write(binary_tx)

        return revision

    async def download(self, bundle):
        vault = self.vault
        if vault is None:
            raise ValueError("Invalid argument")

        logger.info("Downloading %s", bundle)

        dest_path = os.path.join(self.path, bundle.store_hash)

        await bundle.load_key()
        stream = FileReader(dest_path)
        try:
            await vault.crypt_engine.write_encrypted_stream(bundle, stream)
        finally:
            await stream.close()

    async def stat(self, bundle):
        logger.debug("Stat %s", bundle)
        dest_path = os.path.join(self.path, bundle.store_hash)
        if os.path.exists(dest_path + ".hash"):
            metadata = open(dest_path + ".hash", "r")
            content_hash = metadata.read()
            bundle.remote_crypt_hash = content_hash
            metadata.close()

    async def set_vault_metadata(self, identity: Identity) -> Revision:
        vault = self.vault
        if vault is None:
            raise ValueError("Invalid argument")

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
        return {"email": "user@localhost"}

    async def changes(self, since_rev, to_rev) -> RevisionQueue:
        assert since_rev is None or isinstance(since_rev, str)

        queue = cast(RevisionQueue, asyncio.Queue(8))
        asyncio.get_event_loop().create_task(self._changes(since_rev, to_rev, queue))
        return queue

    async def _changes(self, since_rev, to_rev, queue: RevisionQueue):
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
                    await queue.put(rev)
                    rev = pickle.load(txchain)
            except EOFError:
                pass
            finally:
                logger.debug("Finished serving changes")
                await queue.put(None)

    async def delete_file(self, bundle: Bundle, identity: Identity) -> Revision:
        vault = self.vault
        if vault is None:
            raise ValueError("Invalid argument")

        assert vault.revision is not None
        assert bundle.store_hash

        logger.info("Deleting %s", bundle)

        revision = Revision(operation=RevisionOp.DeleteFile)
        revision.vault_id = vault.config.id
        revision.parent_id = vault.revision
        revision.user_id = "user@localhost"
        revision.file_hash = bundle.store_hash
        revision.sign(identity=identity)

        return self.add_revision(revision)

    def set_auth(self, username: str, password: str):
        pass

    async def close(self):
        pass

    async def upload_identity(self, identity: Identity, description: str=""):
        pass

    async def add_vault_user(self, user_id: str, identity: Identity):

        vault = self.vault
        if vault is None:
            raise ValueError("Invalid argument")

        assert vault.revision is not None

        logger.info("Add user %s", user_id)

        revision = Revision(operation=RevisionOp.AddUser)
        revision.vault_id = vault.config.id
        revision.parent_id = vault.revision
        revision.user_id = user_id
        revision.sign(identity=identity)

        return self.add_revision(revision)

    async def remove_vault_user(self, user_id: str, identity: Identity):

        vault = self.vault
        if vault is None:
            raise ValueError("Invalid argument")

        assert vault.revision is not None

        logger.info("Remove user %s", user_id)

        revision = Revision(operation=RevisionOp.RemoveUser)
        revision.vault_id = vault.config.id
        revision.parent_id = vault.revision
        revision.user_id = user_id
        revision.sign(identity=identity)

        return self.add_revision(revision)

    async def add_user_vault_key(self, identity, user_id: str, user_identity: Identity, content):
        pass
