import os
import shutil
import time

import asyncio

from .base import StorageBackend


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
        dest_path = os.path.join(self.path, bundle.file_hash)
        shutil.copyfile(bundle.path, dest_path)
