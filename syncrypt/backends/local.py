import asyncio
import pickle
import logging
import os
import shutil
import time
from glob import glob
from uuid import uuid4

from syncrypt.exceptions import VaultNotInitialized
from syncrypt.pipes import FileReader, FileWriter

from .base import StorageBackend

logger = logging.getLogger(__name__)


class LocalStorageBackend(StorageBackend):

    def __init__(self, vault, folder, **kwargs):
        self.folder = folder
        super(LocalStorageBackend, self).__init__(vault)

        # local storage is always authed
        self.invalid_auth = False
        self.connected = True

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

    async def init(self):
        vault = self.vault
        if not vault.config.get("vault.id"):
            with vault.config.update_context():
                vault.config.update("vault", {"id": str(uuid4())})

        await self.open()  # create directory

        # create txchain store
        with open(os.path.join(self.path, "txchain"), "wb") as txchain:
            pass

        # TODO use random number here
        nonce = str(vault.id).encode()

        # TODO This needs to be signed with the user key, not vault key
        signature = self.vault.identity.sign(b'create_vault|' + nonce)

        revision = self.add_transaction({
            'type': 'create_vault',
            'nonce': nonce,
            'signature': signature,
        })

    async def upload(self, bundle):
        assert self.vault.revision is not None

        logger.info("Uploading %s", bundle)
        dest_path = os.path.join(self.path, bundle.store_hash)
        shutil.copyfile(bundle.path, dest_path)

        metadata = await bundle.encrypted_metadata_reader().readall()
        metadata_size = len(metadata)

        message = b''
        message += str(self.vault.revision).encode() + b'|'
        message += str(bundle.store_hash).encode() + b'|'
        message += str(bundle.crypt_hash).encode() + b'|'
        message += metadata + b'|'
        message += str(bundle.file_size_crypt).encode() + b'|'

        # TODO This needs to be signed with the user key, not vault key
        signature = self.vault.identity.sign(message)

        await bundle.load_key()
        s = bundle.read_encrypted_stream() >> FileWriter(dest_path)
        await s.consume()
        #s = bundle.encrypted_metadata_reader() >> FileWriter(dest_path + ".metadata")
        #await s.consume()
        with open(dest_path + ".hash", "w") as hashfile:
            hashfile.write(bundle.crypt_hash)

        self.add_transaction({
            'type': 'upload',
            'metadata': metadata,
            'signature': signature,
            'store_hash': str(bundle.store_hash).encode(),
            'crypt_hash': str(bundle.crypt_hash).encode(),
            'file_size_crypt': bundle.file_size_crypt
        })

    def add_transaction(self, obj):
        revision_id = str(uuid4())
        revision = dict(obj, id=revision_id)

        with open(os.path.join(self.path, "txchain"), "ab") as txchain:
            logger.debug('Adding revision %s to signchain.', revision['id'])
            binary_tx = pickle.dumps(revision)
            txchain.write(binary_tx)

        # update vault revision
        # TODO is there a better way to do this? Outside of storage backend?
        self.vault.update_revision(revision['id'])

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
        raise NotImplementedError

    async def close(self):
        pass
