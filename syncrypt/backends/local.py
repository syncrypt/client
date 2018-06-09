import asyncio
import logging
import math
import os
import pickle
import shutil
import time
from glob import glob
from uuid import uuid4

from Cryptodome.Random.random import randint

from syncrypt.exceptions import VaultNotInitialized
from syncrypt.models import Revision, RevisionOp, Vault
from syncrypt.pipes import FileReader, FileWriter

from .base import StorageBackend

logger = logging.getLogger(__name__)


class LocalStorageBackend(StorageBackend):
    def __init__(self, vault: Vault, folder, **kwargs) -> None:
        self.folder = folder
        self.vault = vault

    @property
    def path(self):
        if self.vault and not self.vault.config.get("vault.id"):
            raise VaultNotInitialized()

        # folder can be relative to vault
        return os.path.join(
            self.vault.folder, self.folder, self.vault.config.get("vault.id")
        )

    async def open(self):
        if not os.path.isdir(self.path):
            os.makedirs(self.path, exist_ok=True)

    async def init(self) -> Revision:
        vault = self.vault
        new_vault_id = str(uuid4())
        if not vault.config.get("vault.id"):
            with vault.config.update_context():
                vault.config.update("vault", {"id": new_vault_id})

        await self.open()  # create directory

        # create txchain store
        with open(os.path.join(self.path, "txchain"), "wb") as txchain:
            pass

        identity = vault.identity # TODO use user identity here

        transaction = Revision(operation=RevisionOp.CreateVault)
        transaction.nonce = randint(0, 0xffffffff)
        transaction.vault_id = new_vault_id
        transaction.user_id = 'user@localhost'
        transaction.user_fingerprint = identity.get_fingerprint()
        transaction.public_key = identity.public_key.exportKey('DER')
        transaction.sign(identity=identity)

        return self.add_transaction(transaction)

    async def upload(self, bundle) -> Revision:
        assert self.vault.revision is not None

        logger.info("Uploading %s", bundle)
        dest_path = os.path.join(self.path, bundle.store_hash)
        shutil.copyfile(bundle.path, dest_path)

        metadata = await bundle.encrypted_metadata_reader().readall()
        metadata_size = len(metadata)

        await bundle.load_key()
        s = bundle.read_encrypted_stream() >> FileWriter(dest_path)
        await s.consume()
        #s = bundle.encrypted_metadata_reader() >> FileWriter(dest_path + ".metadata")
        #await s.consume()
        with open(dest_path + ".hash", "w") as hashfile:
            hashfile.write(bundle.crypt_hash)

        identity = self.vault.identity # TODO use user identity here

        transaction = Revision(operation=RevisionOp.Upload)
        transaction.vault_id = self.vault.id
        transaction.parent_id = self.vault.revision
        transaction.user_id = 'user@localhost'
        transaction.user_fingerprint = identity.get_fingerprint()
        transaction.file_hash = bundle.store_hash
        transaction.revision_metadata = metadata
        transaction.crypt_hash = bundle.crypt_hash
        transaction.file_size_crypt = bundle.file_size_crypt
        transaction.sign(identity=identity)

        return self.add_transaction(transaction)

    def add_transaction(self, revision: Revision):
        if revision.id is not None:
            raise ValueError('Transaction already has an id.')

        if revision.signature is None:
            raise ValueError('Transaction is not signed.')

        revision.id = str(uuid4())

        with open(os.path.join(self.path, "txchain"), "ab") as txchain:
            logger.debug('Adding revision %s to signchain.', revision.id)
            binary_tx = pickle.dumps(revision)
            txchain.write(binary_tx)

        return revision

    async def download(self, bundle):
        logger.info("Downloading %s", bundle)

        dest_path = os.path.join(self.path, bundle.store_hash)

        await bundle.load_key()
        s = FileReader(dest_path)
        try:
            await bundle.write_encrypted_stream(s)
        finally:
            await s.close()

    async def stat(self, bundle):
        logger.debug("Stat %s", bundle)
        dest_path = os.path.join(self.path, bundle.store_hash)
        if os.path.exists(dest_path + ".hash"):
            metadata = open(dest_path + ".hash", "r")
            content_hash = metadata.read()
            bundle.remote_crypt_hash = content_hash
            metadata.close()

    async def set_vault_metadata(self):
        dest_path = os.path.join(self.path, "metadata")
        writer = self.vault.encrypted_metadata_reader() >> FileWriter(
            dest_path, create_dirs=True
        )
        await writer.consume()

    async def vault_metadata(self):
        dest_path = os.path.join(self.path, "metadata")
        await self.vault.write_encrypted_metadata(FileReader(dest_path))

    async def list_files(self):
        logger.info("Listing files")
        queue = asyncio.Queue()
        for f in glob(os.path.join(self.path, "*.metadata")):
            base, ext = os.path.splitext(os.path.basename(f))
            with open(f, "rb") as f:
                metadata = f.read()
            await queue.put((base, metadata, {}))
        await queue.put(None)
        return queue

    async def user_info(self):
        return {"email": "user@localhost"}

    async def changes(self, since_rev, to_rev, verbose=False):
        assert since_rev is None or isinstance(since_rev, str)

        queue = asyncio.Queue(8)
        task = asyncio.get_event_loop().create_task(self._changes(since_rev, to_rev, queue))
        return queue

    async def _changes(self, since_rev, to_rev, queue):
        with open(os.path.join(self.path, "txchain"), "rb") as txchain:
            try:
                if since_rev:
                    # Skip until since_rev
                    rev = pickle.load(txchain)
                    while rev.id != since_rev:
                        rev = pickle.load(txchain)

                rev = pickle.load(txchain)

                while rev.id != to_rev:
                    await queue.put(rev)
                    rev = pickle.load(txchain)
            except EOFError:
                pass
            finally:
                await queue.put(None)

    async def close(self):
        pass
