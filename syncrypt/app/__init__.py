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
    '''This is the Syncrypt daemon that can orchestrate multiple vaults and
    report status via a HTTP interface'''
    # TODO rename to SyncryptDaemon

    def __init__(self, config):
        self.vaults = []
        self.config = config
        self.concurrency = int(self.config.app['concurrency'])
        self.bundle_action_semaphore = JoinableSemaphore(self.concurrency)
        self.watchdogs = {}
        self.api = SyncryptAPI(self)
        super(SyncryptApp, self).__init__()

    def add_vault(self, vault):
        self.vaults.append(vault)

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
    def open_or_init(self, vault):
        try:
            yield from vault.backend.open()
        except StorageBackendInvalidAuth:
            # retry after logging in & getting auth token
            yield from vault.backend.init()
            yield from open_or_init(vault)

    @asyncio.coroutine
    def start(self):
        yield from self.api.start_web()
        yield from self.push()
        for vault in self.vaults:
            logger.info('Watching %s', os.path.abspath(vault.folder))
            self.watchdogs[vault.folder] = AIOWatchdog(vault.folder, event_handler=self)
            self.watchdogs[vault.folder].start()

    @asyncio.coroutine
    def stop(self):
        for watchdog in self.watchdogs.values():
            watchdog.stop()

    @asyncio.coroutine
    def on_modified(self, event):
        bundle = self.vault.bundle_for(os.path.relpath(event.src_path, self.vault.folder))
        if not bundle is None:
            bundle.schedule_update()

    @asyncio.coroutine
    def push(self):
        for vault in self.vaults:
            yield from self.open_or_init(vault)
            for bundle in vault.walk():
                yield from self.bundle_action_semaphore.acquire()
                task = asyncio.Task(self.push_bundle(vault.backend, bundle))
                asyncio.get_event_loop().call_soon(task)
        yield from self.bundle_action_semaphore.join()

    @asyncio.coroutine
    def pull(self):
        for vault in self.vaults:
            yield from self.open_or_init(vault)
            for bundle in vault.walk():
                yield from self.bundle_action_semaphore.acquire()
                task = asyncio.Task(self.pull_bundle(vault.backend, bundle))
                asyncio.get_event_loop().call_soon(task)
        yield from self.bundle_action_semaphore.join()

    @asyncio.coroutine
    def push_bundle(self, backend, bundle):
        'update bundle and maybe upload'
        yield from bundle.update()
        yield from backend.stat(bundle)
        if bundle.remote_hash_differs:
            yield from backend.upload(bundle)
        logger.debug('Release action semaphore')
        yield from self.bundle_action_semaphore.release()
        logger.debug('Released action semaphore')

    @asyncio.coroutine
    def pull_bundle(self, backend, bundle):
        'update, maybe download, and then decrypt'
        yield from bundle.update()
        yield from backend.stat(bundle)
        if bundle.remote_hash_differs:
            yield from backend.download(bundle)
        yield from self.bundle_action_semaphore.release()

