import logging
import os
import shutil
import time

import asyncio

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
        file_info = open(dest_path + '.file_info', 'w')
        file_info.write(bundle.crypt_hash)
        file_info.close()

    @asyncio.coroutine
    def stat(self, bundle):
        logger.info('Stat %s', bundle)
        dest_path = os.path.join(self.path, bundle.store_hash)
        if os.path.exists(dest_path + '.file_info'):
            file_info = open(dest_path + '.file_info', 'r')
            content_hash = file_info.read()
            bundle.remote_crypt_hash = content_hash
            file_info.close()

