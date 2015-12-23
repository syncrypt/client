import logging
import os.path
import sys

import asyncio
from hachiko.hachiko import AIOEventHandler, AIOWatchdog
from syncrypt import Vault
from syncrypt.backends.base import StorageBackendInvalidAuth
from syncrypt.limiter import JoinableSemaphore

logger = logging.getLogger(__name__)

class SyncryptApp(AIOEventHandler):

    def __init__(self, vault):
        self.vault = vault
        self.bundle_action_semaphore = JoinableSemaphore(8)
        super(SyncryptApp, self).__init__()

    @asyncio.coroutine
    def init(self):
        try:
            yield from self.vault.backend.open()
            logger.warn('Vault already initialized')
            return
        except StorageBackendInvalidAuth:
            pass
        yield from self.vault.backend.init()

    @asyncio.coroutine
    def open_or_init(self):
        try:
            yield from self.vault.backend.open()
        except StorageBackendInvalidAuth:
            # retry after logging in & getting auth token
            yield from self.vault.backend.init()
            yield from self.open_or_init()

    @asyncio.coroutine
    def start(self):
        yield from self.open_or_init()
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
        yield from self.open_or_init()
        for bundle in self.vault.walk():
            yield from self.bundle_action_semaphore.acquire()
            task = asyncio.Task(self.push_bundle(self.vault.backend, bundle))
            asyncio.get_event_loop().call_soon(task)
        yield from self.bundle_action_semaphore.join()

    @asyncio.coroutine
    def pull(self):
        yield from self.open_or_init()
        for bundle in self.vault.walk():
            yield from self.bundle_action_semaphore.acquire()
            task = asyncio.Task(self.pull_bundle(self.vault.backend, bundle))
            asyncio.get_event_loop().call_soon(task)
        yield from self.bundle_action_semaphore.join()

    @asyncio.coroutine
    def push_bundle(self, backend, bundle):
        'update bundle and maybe upload'
        yield from bundle.update()
        yield from backend.stat(bundle)
        if bundle.remote_hash_differs:
            yield from backend.upload(bundle)
        yield from self.bundle_action_semaphore.release()

    @asyncio.coroutine
    def pull_bundle(self, backend, bundle):
        'update, maybe download, and then decrypt'
        yield from self.bundle_action_semaphore.acquire()
        yield from bundle.update()
        yield from backend.stat(bundle)
        if bundle.remote_hash_differs:
            yield from backend.download(bundle)
        yield from self.bundle_action_semaphore.release()

