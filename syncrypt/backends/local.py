import logging
import os
import shutil
import time
from glob import glob

import asyncio
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
        # folder is relative to vault
        return os.path.join(self.vault.folder, self.folder)

    async def open(self):
        if not os.path.isdir(self.path):
            os.makedirs(self.path)

    async def upload(self, bundle):
        logger.info('Uploading %s', bundle)
        dest_path = os.path.join(self.path, bundle.store_hash)
        shutil.copyfile(bundle.path, dest_path)
        await bundle.load_key()
        s = bundle.read_encrypted_stream() >> FileWriter(dest_path)
        await s.consume()
        s = bundle.encrypted_metadata_reader() >> FileWriter(dest_path + '.metadata')
        await s.consume()
        metadata = open(dest_path + '.hash', 'w')
        metadata.write(bundle.crypt_hash)
        metadata.close()

    async def download(self, bundle):
        logger.info('Downloading %s', bundle)

        dest_path = os.path.join(self.path, bundle.store_hash)

        await bundle.load_key()
        s = FileReader(dest_path)
        try:
            await bundle.write_encrypted_stream(s)
        finally:
            await s.close()

    async def stat(self, bundle):
        logger.debug('Stat %s', bundle)
        dest_path = os.path.join(self.path, bundle.store_hash)
        if os.path.exists(dest_path + '.metadata'):
            metadata = open(dest_path + '.hash', 'r')
            content_hash = metadata.read()
            bundle.remote_crypt_hash = content_hash
            metadata.close()

    async def set_vault_metadata(self):
        dest_path = os.path.join(self.path, 'metadata')
        writer = self.vault.encrypted_metadata_reader() \
                >> FileWriter(dest_path, create_dirs=True)
        await writer.consume()

    async def vault_metadata(self):
        dest_path = os.path.join(self.path, 'metadata')
        await self.vault.write_encrypted_metadata(FileReader(dest_path))

    async def list_files(self):
        logger.info('Listing files')
        queue = asyncio.Queue()
        for f in (glob(os.path.join(self.path, '*.metadata'))):
            base, ext = os.path.splitext(os.path.basename(f))
            with open(f, 'rb') as f:
                metadata = f.read()
            await queue.put((base, metadata, {}))
        await queue.put(None)
        return queue

    async def close(self):
        pass
