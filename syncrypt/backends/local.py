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

    def __init__(self, vault, folder):
        self.folder = folder
        super(LocalStorageBackend, self).__init__(vault)

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
        s = bundle.encrypted_fileinfo_reader() >> FileWriter(dest_path + '.file_info')
        yield from s.consume()
        file_info = open(dest_path + '.hash', 'w')
        file_info.write(bundle.crypt_hash)
        file_info.close()

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
        logger.info('Stat %s', bundle)
        dest_path = os.path.join(self.path, bundle.store_hash)
        if os.path.exists(dest_path + '.file_info'):
            file_info = open(dest_path + '.hash', 'r')
            content_hash = file_info.read()
            bundle.remote_crypt_hash = content_hash
            file_info.close()

    @asyncio.coroutine
    def list_files(self):
        logger.info('Listing files')
        for f in (glob(os.path.join(self.path, '*.file_info'))):
            base, ext = os.path.splitext(os.path.basename(f))
            with open(f, 'rb') as f:
                file_info = f.read()
            yield from self.vault.add_bundle_by_fileinfo(base, file_info)

    @asyncio.coroutine
    def close(self):
        pass
