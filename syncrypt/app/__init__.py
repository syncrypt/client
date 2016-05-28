import logging
import os.path
import sys
from io import StringIO

import asyncio
from hachiko.hachiko import AIOEventHandler, AIOWatchdog
from syncrypt.backends.base import StorageBackendInvalidAuth
from syncrypt.exceptions import VaultNotInitialized
from syncrypt.models import Identity, Vault, VirtualBundle
from syncrypt.pipes import Once, FileWriter
from syncrypt.utils.format import format_fingerprint, format_size
from syncrypt.utils.semaphores import JoinableSemaphore
from syncrypt.vendor.keyart import draw_art

from .api import SyncryptAPI

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
            self.app.schedule_update(bundle)
        else:
            logger.debug('Ignoring file creation: %s', path)

    @asyncio.coroutine
    def on_file_removed(self, path):
        bundle = self.vault.bundle_for(os.path.relpath(path, self.vault.folder))
        if not bundle is None:
            logger.info('File delete detected (%s)', bundle)
        else:
            logger.debug('Ignoring file delete: %s', path)

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

        # map from Bundle -> Future
        self.update_handles = {}

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

    def update_and_upload(self, bundle):
        del self.update_handles[bundle]
        def _update(bundle):
            logger.debug('Scheduled update is executing for %s', bundle)
            yield from bundle.update()
            yield from bundle.vault.backend.stat(bundle)
            if bundle.remote_hash_differs:
                yield from bundle.vault.backend.upload(bundle)
        asyncio.ensure_future(_update(bundle))

    def schedule_update(self, bundle):
        if bundle in self.update_handles:
            self.update_handles[bundle].cancel()
        loop = asyncio.get_event_loop()
        self.update_handles[bundle] = loop.call_later(1.0, self.update_and_upload, bundle)

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
            yield from vault.backend.upload_identity()

    @asyncio.coroutine
    def upload_identity(self):
        for vault in self.vaults:
            yield from vault.backend.upload_identity()

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
    def list_keys(self, user=None):
        for key in (yield from self.vaults[0].backend.list_keys(user)):
            print(key)

    @asyncio.coroutine
    def info(self):
        for (index, vault) in enumerate(self.vaults):
            yield from self.retrieve_metadata(vault)
            remote_size = yield from self.get_remote_size_for_vault(vault)
            print("="*78, end='\n\n')
            print("Vault {0}".format(index + 1))
            print()
            print(draw_art(None, '1', vault.identity.get_fingerprint()))
            print()
            print("Vault name:       \t{0}".format(vault.config.vault.get('name', 'Unnamed')))
            print("Vault ID:         \t{0}".format(vault.config.id))
            print("Vault revision:   \t{0}".format(vault.revision or '?'))
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
    def set(self, setting, value):
        for vault in self.vaults:
            vault.config.set(setting, value)
            vault.write_config()

    @asyncio.coroutine
    def unset(self, setting):
        for vault in self.vaults:
            vault.config.unset(setting)
            vault.write_config()

    @asyncio.coroutine
    def export(self, filename):
        vault = self.vaults[0]
        export_pipe = vault.package_info() >> FileWriter(filename)
        yield from export_pipe.consume()
        logger.info("Vault export has been written to: %s" % filename)

    @asyncio.coroutine
    def print_log(self):
        for vault in self.vaults:
            yield from vault.backend.open()
            queue = yield from vault.backend.changes(None, None)
            while True:
                item = yield from queue.get()
                if item is None:
                    break
                store_hash, metadata, server_info = item
                bundle = VirtualBundle(None, vault, store_hash=store_hash)
                yield from bundle.write_encrypted_metadata(Once(metadata))
                created_at = server_info['created_at'].decode(vault.config.encoding)
                operation = server_info['operation'].decode(vault.config.encoding)
                print("%-27s %-9s %s" % (created_at, operation, bundle.relpath))
        yield from self.wait()

    @asyncio.coroutine
    def push(self):
        for vault in self.vaults:
            yield from vault.backend.open()
            yield from vault.backend.set_vault_metadata()
            for bundle in vault.walk_disk():
                yield from self.push_bundle(bundle)
        yield from self.wait()

    @asyncio.coroutine
    def get_remote_size_for_vault(self, vault):
        yield from vault.backend.open()
        return (yield from vault.backend.vault_size(vault))

    @asyncio.coroutine
    def retrieve_metadata(self, vault):
        yield from vault.backend.open()
        return (yield from vault.backend.vault_metadata())

    @asyncio.coroutine
    def pull(self):
        # TODO: do a change detection (.vault/metadata store vs filesystem)
        for vault in self.vaults:
            yield from self.open_or_init(vault)
            if vault.revision:
                queue = yield from vault.backend.changes(vault.revision, None)
            else:
                queue = yield from vault.backend.list_files()
            while True:
                item = yield from queue.get()
                if item is None:
                    break
                store_hash, metadata, server_info = item
                bundle = yield from vault.add_bundle_by_metadata(store_hash, metadata)
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

