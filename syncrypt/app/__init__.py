import logging
import os.path
import sys

import asyncio
from hachiko.hachiko import AIOEventHandler, AIOWatchdog
from syncrypt import Vault
from syncrypt.backends.base import StorageBackendInvalidAuth
from syncrypt.utils.semaphores import JoinableSemaphore

from .api import SyncryptAPI
from syncrypt.utils.format import format_fingerprint, format_size
from syncrypt.identity import Identity
from syncrypt.exceptions import VaultNotInitialized

logger = logging.getLogger(__name__)

class VaultEventHandler(AIOEventHandler):

    def __init__(self, app, vault):
        self.app = app
        self.vault = vault
        super(VaultEventHandler, self).__init__()

    @asyncio.coroutine
    def on_file_changed(self, path):
        bundle = self.vault.bundle_for(os.path.relpath(path, self.vault.folder))
        if not bundle is None:
            logger.info('File creation detected (%s)', bundle)
            bundle.schedule_update()
        else:
            logger.debug('Ignoring file creation: %s', event.src_path)

    @asyncio.coroutine
    def on_file_removed(self, path):
        bundle = self.vault.bundle_for(os.path.relpath(path, self.vault.folder))
        if not bundle is None:
            logger.info('File delete detected (%s)', bundle)
        else:
            logger.debug('Ignoring file delete: %s', event.src_path)

    @asyncio.coroutine
    def on_deleted(self, event):
        yield from self.on_file_removed(event.dest_path)

    @asyncio.coroutine
    def on_moved(self, event):
        yield from self.on_file_changed(event.dest_path)
        yield from self.on_file_removed(event.src_path)

    @asyncio.coroutine
    def on_created(self, event):
        yield from self.on_file_changed(event.src_path)

    @asyncio.coroutine
    def on_modified(self, event):
        yield from self.on_file_changed(event.src_path)

class SyncryptApp(object):
    '''
    The Syncrypt daemon app that can orchestrate multiple vaults and report
    status via a HTTP interface. It is designed to be the cross-platform
    core of syncrypt-desktop.
    '''

    def __init__(self, config, auth_provider=None):
        self.auth_provider = auth_provider
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

        def handler(*args, **kwargs):
            logger.error("%s, %s", args, kwargs)
        asyncio.get_event_loop().set_exception_handler(handler)

        # generate or read users identity
        id_rsa_path = os.path.join(self.config.config_dir, 'id_rsa')
        id_rsa_pub_path = os.path.join(self.config.config_dir, 'id_rsa.pub')
        self.identity = Identity(id_rsa_path, id_rsa_pub_path, self.config)
        self.identity.init()

        # register vault objects
        for vault_dir in self.config.vault_dirs:
            self.vaults.append(Vault(vault_dir))

        super(SyncryptApp, self).__init__()

    def add_vault_by_path(self, path):
        return self.add_vault(Vault(path))

    def add_vault(self, vault):
        self.vaults.append(vault)
        self.config.add_vault_dir(os.path.abspath(vault.folder))
        return vault

    def remove_vault(self, vault):
        # TODO: close open connections etc
        self.config.remove_vault_dir(os.path.abspath(vault.folder))
        self.vaults.remove(vault)

    @asyncio.coroutine
    def init(self, vault=None):
        for vault in (self.vaults if vault is None else [vault]):
            try:
                yield from vault.backend.open()
                logger.warn('Vault %s already initialized', vault.folder)
                continue
            except StorageBackendInvalidAuth:
                pass
            except VaultNotInitialized:
                pass
            logger.info("Initializing %s", vault)
            vault.identity.init()
            username, password = yield from self.auth_provider.get_auth(vault)
            vault.set_auth(username, password)
            yield from vault.backend.init()

    @asyncio.coroutine
    def open_or_init(self, vault):
        try:
            yield from vault.backend.open()
        except StorageBackendInvalidAuth:
            # retry after logging in & getting auth token
            yield from self.init(vault)
            yield from vault.backend.open()

    @asyncio.coroutine
    def start(self):
        yield from self.api.start()
        yield from self.push()
        for vault in self.vaults:
            logger.info('Watching %s', os.path.abspath(vault.folder))
            self.watchdogs[vault.folder] = \
                    AIOWatchdog(vault.folder, event_handler=VaultEventHandler(self, vault))
            self.watchdogs[vault.folder].start()

    @asyncio.coroutine
    def stop(self):
        for watchdog in self.watchdogs.values():
            watchdog.stop()
        yield from self.api.stop()

    @asyncio.coroutine
    def push_bundle(self, bundle):
        yield from self.bundle_action_semaphore.acquire()
        task = asyncio.get_event_loop().create_task(self._push_bundle(bundle))
        def cb(_task):
            if task.exception():
                from traceback import format_tb
                ex = task.exception()
                logger.warn("Got exception: %s %s %s", ex, type(ex),
                        format_tb(ex.__traceback__))
            asyncio.get_event_loop().create_task(self.bundle_action_semaphore.release())
        task.add_done_callback(cb)

    @asyncio.coroutine
    def pull_bundle(self, bundle):
        yield from self.bundle_action_semaphore.acquire()
        task = asyncio.get_event_loop().create_task(self._pull_bundle(bundle))
        def cb(_task):
            if task.exception():
                from traceback import format_tb
                ex = task.exception()
                logger.warn("Got exception: %s %s %s", ex, type(ex),
                        format_tb(ex.__traceback__))
            asyncio.get_event_loop().create_task(self.bundle_action_semaphore.release())
        task.add_done_callback(cb)

    @asyncio.coroutine
    def clone(self, clone_target):
        import shutil
        import os

        vault = self.vaults[0]

        yield from self.push()

        if not os.path.exists(clone_target):
            os.makedirs(clone_target)

        vault_cfg = os.path.join(clone_target, '.vault')
        if not os.path.exists(vault_cfg):
            os.makedirs(vault_cfg)

        for f in ('config', 'id_rsa', 'id_rsa.pub'):
            shutil.copyfile(os.path.join(vault.folder, '.vault', f), os.path.join(vault_cfg, f))

        logger.info("Cloned %s to %s" % (vault.folder, os.path.abspath(clone_target)))

        self.add_vault(Vault(clone_target))

        yield from self.pull()

    @asyncio.coroutine
    def info(self):
        for (index, vault) in enumerate(self.vaults):
            remote_size = yield from self.get_remote_size_for_vault(vault)
            revision = 'revision' in vault.config.vault and vault.config.vault['revision'] or '?'
            print("="*78, end='\n\n')
            print("Vault {0}".format(index + 1))
            print()
            print("Vault ID:         \t{0}".format(vault.config.id))
            print("Vault name:       \t{0}".format('Unnamed'))
            print("Vault revision:   \t{0}".format(revision))
            print("Vault fingerprint:\t{0}".format(format_fingerprint(
                    vault.identity.get_fingerprint())))
            print("Local directory:  \t{0}".format(os.path.abspath(vault.folder)))
            print("Local size:       \t{0} (includes metadata)".format(format_size(
                    vault.get_local_size())))
            print("Remote size:      \t{0} (includes versioned copies)".format(format_size(
                    remote_size)))
            print("Your fingerprint: \t{0}".format(format_fingerprint(
                    self.identity.get_fingerprint())))
            print()
        print("="*78)

    def get_vault_states(self):
        return {v.folder: v.state for v in self.vaults}

    @asyncio.coroutine
    def push(self):
        for vault in self.vaults:
            yield from vault.backend.open()
            for bundle in vault.walk_disk():
                yield from self.push_bundle(bundle)
        yield from self.wait()

    @asyncio.coroutine
    def get_remote_size_for_vault(self, vault):
        yield from vault.backend.open()
        return (yield from vault.backend.vault_size(vault))

    @asyncio.coroutine
    def pull(self):
        for vault in self.vaults:
            yield from self.open_or_init(vault)
            yield from self.retrieve_bundle_list(vault)
            for bundle in vault.walk():
                yield from self.pull_bundle(bundle)
        yield from self.wait()

    @asyncio.coroutine
    def wait(self):
        yield from self.bundle_action_semaphore.join()

    @asyncio.coroutine
    def close(self):
        yield from self.wait()
        for vault in self.vaults:
            yield from vault.close()

    @asyncio.coroutine
    def _push_bundle(self, bundle):
        'update bundle and maybe upload'
        yield from bundle.update()

        yield from bundle.vault.semaphores['stat'].acquire(bundle)
        yield from bundle.vault.backend.stat(bundle)
        self.stats['stats'] += 1
        yield from bundle.vault.semaphores['stat'].release(bundle)
        if bundle.remote_hash_differs:
            yield from bundle.vault.semaphores['upload'].acquire(bundle)
            yield from bundle.vault.backend.upload(bundle)
            self.stats['uploads'] += 1
            yield from bundle.vault.semaphores['upload'].release(bundle)

    @asyncio.coroutine
    def _pull_bundle(self, bundle):
        'update, maybe download, and then decrypt'
        yield from bundle.update()
        yield from bundle.vault.semaphores['stat'].acquire(bundle)
        yield from bundle.vault.backend.stat(bundle)
        self.stats['stats'] += 1
        yield from bundle.vault.semaphores['stat'].release(bundle)
        if bundle.remote_crypt_hash is None:
            logger.warn('File not found: %s', bundle)
            return
        if bundle.remote_hash_differs:
            yield from bundle.vault.semaphores['download'].acquire(bundle)
            yield from bundle.vault.backend.download(bundle)
            self.stats['downloads'] += 1
            yield from bundle.vault.semaphores['download'].release(bundle)

