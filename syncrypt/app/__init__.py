import logging
import os.path
import sys

import asyncio
from hachiko.hachiko import AIOEventHandler, AIOWatchdog
from syncrypt import Vault
from syncrypt.backends.base import StorageBackendInvalidAuth
from syncrypt.utils.limiter import JoinableSemaphore
from .api import SyncryptAPI

logger = logging.getLogger(__name__)

class SyncryptApp(AIOEventHandler):
    '''
    The Syncrypt daemon app that can orchestrate multiple vaults and report
    status via a HTTP interface. It is designed to be the cross-platform
    core of syncrypt-desktop.
    '''

    def __init__(self, config):
        self.vaults = []
        self.config = config
        self.concurrency = int(self.config.app['concurrency'])
        self.bundle_action_semaphore = JoinableSemaphore(self.concurrency)
        self.watchdogs = {}
        self.api = SyncryptAPI(self)
        self.stats = {
            'uploads': 0,
            'downloads': 0,
            'stats': 0
            }
        super(SyncryptApp, self).__init__()

    def add_vault(self, vault):
        self.vaults.append(vault)

    @asyncio.coroutine
    def init(self):
        for vault in self.vaults:
            try:
                yield from vault.backend.open()
                logger.warn('Vault %s already initialized', vault.folder)
                continue
            except StorageBackendInvalidAuth:
                pass
            yield from vault.backend.init()

    @asyncio.coroutine
    def open_or_init(self, vault):
        try:
            yield from vault.backend.open()
        except StorageBackendInvalidAuth:
            # retry after logging in & getting auth token
            yield from vault.backend.init()
            yield from open_or_init(vault)

    @asyncio.coroutine
    def start(self):
        yield from self.api.start()
        yield from self.push()
        for vault in self.vaults:
            logger.info('Watching %s', os.path.abspath(vault.folder))
            self.watchdogs[vault.folder] = AIOWatchdog(vault.folder, event_handler=self)
            self.watchdogs[vault.folder].start()

    @asyncio.coroutine
    def stop(self):
        for watchdog in self.watchdogs.values():
            watchdog.stop()
        yield from self.api.stop()

    @asyncio.coroutine
    def on_modified(self, event):
        bundle = self.vault.bundle_for(os.path.relpath(event.src_path, self.vault.folder))
        if not bundle is None:
            bundle.schedule_update()

    @asyncio.coroutine
    def push_bundle(self, bundle):
        yield from self.bundle_action_semaphore.acquire()
        asyncio.get_event_loop().create_task(self._push_bundle(bundle))

    @asyncio.coroutine
    def pull_bundle(self, bundle):
        yield from self.bundle_action_semaphore.acquire()
        asyncio.get_event_loop().create_task(self._pull_bundle(bundle))

    @asyncio.coroutine
    def push(self):
        for vault in self.vaults:
            yield from self.open_or_init(vault)
            for bundle in vault.walk():
                yield from self.push_bundle(bundle)
        yield from self.wait()

    @asyncio.coroutine
    def pull(self):
        for vault in self.vaults:
            yield from self.open_or_init(vault)
            for bundle in vault.walk():
                yield from self.pull_bundle(bundle)
        yield from self.wait()

    @asyncio.coroutine
    def wait(self):
        yield from self.bundle_action_semaphore.join()

    @asyncio.coroutine
    def _push_bundle(self, bundle):
        'update bundle and maybe upload'
        yield from bundle.update()
        yield from bundle.vault.backend.stat(bundle)
        self.stats['stats'] += 1
        if bundle.remote_hash_differs:
            yield from bundle.vault.backend.upload(bundle)
            self.stats['uploads'] += 1
        yield from self.bundle_action_semaphore.release()

    @asyncio.coroutine
    def _pull_bundle(self, bundle):
        'update, maybe download, and then decrypt'
        yield from bundle.update()
        yield from bundle.vault.backend.backend.stat(bundle)
        self.stats['stats'] += 1
        if bundle.remote_hash_differs:
            yield from bundle.vault.backend.download(bundle)
            self.stats['downloads'] += 1
        yield from self.bundle_action_semaphore.release()

