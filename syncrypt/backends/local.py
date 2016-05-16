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

    @asyncio.coroutine
    def open(self):
        if not os.path.isdir(self.path):
            os.makedirs(self.path)

    @asyncio.coroutine
    def upload(self, bundle):
        logger.info('Uploading %s', bundle)
        dest_path = os.path.join(self.path, bundle.store_hash)
        shutil.copyfile(bundle.path, dest_path)
        yield from bundle.load_key()
        s = bundle.read_encrypted_stream() >> FileWriter(dest_path)
        yield from s.consume()
        s = bundle.encrypted_metadata_reader() >> FileWriter(dest_path + '.metadata')
        yield from s.consume()
        metadata = open(dest_path + '.hash', 'w')
        metadata.write(bundle.crypt_hash)
        metadata.close()

    @asyncio.coroutine
    def download(self, bundle):
        logger.info('Downloading %s', bundle)

        dest_path = os.path.join(self.path, bundle.store_hash)

        yield from bundle.load_key()
        s = FileReader(dest_path)
        try:
            yield from bundle.write_encrypted_stream(s)
        finally:
            yield from s.close()

    @asyncio.coroutine
    def stat(self, bundle):
        logger.debug('Stat %s', bundle)
        dest_path = os.path.join(self.path, bundle.store_hash)
        if os.path.exists(dest_path + '.metadata'):
            metadata = open(dest_path + '.hash', 'r')
            content_hash = metadata.read()
            bundle.remote_crypt_hash = content_hash
            metadata.close()

    @asyncio.coroutine
    def set_vault_metadata(self):
        dest_path = os.path.join(self.path, 'metadata')
        writer = self.vault.encrypted_metadata_reader() \
                >> FileWriter(dest_path, create_dirs=True)
        yield from writer.consume()

    @asyncio.coroutine
    def vault_metadata(self):
        dest_path = os.path.join(self.path, 'metadata')
        yield from self.vault.write_encrypted_metadata(FileReader(dest_path))

    @asyncio.coroutine
    def list_files(self):
        logger.info('Listing files')
        queue = asyncio.Queue()
        for f in (glob(os.path.join(self.path, '*.metadata'))):
            base, ext = os.path.splitext(os.path.basename(f))
            with open(f, 'rb') as f:
                metadata = f.read()
            yield from queue.put((base, metadata, {}))
        yield from queue.put(None)
        return queue

    @asyncio.coroutine
    def close(self):
        pass
