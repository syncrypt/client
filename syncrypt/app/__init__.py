import logging
import os.path
import sys

import asyncio
from hachiko.hachiko import AIOEventHandler, AIOWatchdog
from syncrypt import Vault

logger = logging.getLogger(__name__)

class SyncryptApp(AIOEventHandler):
    def __init__(self, vault):
        self.vault = vault
        super(SyncryptApp, self).__init__()

    @asyncio.coroutine
    def start(self):
        yield from self.vault.backend.open()
        yield from self.push()
        logger.info('Watching %s', os.path.abspath(self.vault.folder))
        self.watchdog = AIOWatchdog(self.vault.folder, event_handler=self)
        self.watchdog.start()

    @asyncio.coroutine
    def stop(self):
        self.watchdog.stop()

    @asyncio.coroutine
    def on_modified(self, event):
        bundle = self.vault.bundle_for(os.path.relpath(event.src_path, self.vault.folder))
        if not bundle is None:
            bundle.schedule_update()

    @asyncio.coroutine
    def push(self):
        yield from asyncio.wait([
            asyncio.ensure_future(self.push_bundle(self.vault.backend, bundle))
                for bundle in self.vault.walk()])

    @asyncio.coroutine
    def pull(self):
        yield from asyncio.wait([
            asyncio.ensure_future(self.pull_bundle(self.vault.backend, bundle))
                for bundle in self.vault.walk()])

    @asyncio.coroutine
    def push_bundle(self, backend, bundle):
        'encrypt bundle and maybe upload'
        yield from bundle.encrypt()
        yield from backend.stat(bundle)
        if bundle.remote_hash_differs:
            yield from backend.upload(bundle)

    @asyncio.coroutine
    def pull_bundle(self, backend, bundle):
        'encrypt, maybe download, and then decrypt'
        yield from bundle.encrypt()
        yield from backend.stat(bundle)
        if bundle.remote_hash_differs:
            yield from backend.download(bundle)
            yield from bundle.decrypt()


