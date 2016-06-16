import logging
import socket
import os.path
import sys
from io import StringIO

import asyncio
import iso8601
from syncrypt.backends.base import StorageBackendInvalidAuth
from syncrypt.backends.binary import BinaryStorageBackend
from syncrypt.exceptions import VaultNotInitialized
from syncrypt.models import Identity, Vault, VirtualBundle
from syncrypt.pipes import (DecryptRSA_PKCS1_OAEP, EncryptRSA_PKCS1_OAEP,
                            FileWriter, Once, SnappyCompress, StdoutWriter)
from syncrypt.utils.format import format_fingerprint, format_size
from syncrypt.utils.semaphores import JoinableSemaphore
from syncrypt.vendor.keyart import draw_art
from tzlocal import get_localzone

from .api import SyncryptAPI
from .events import create_watchdog

logger = logging.getLogger(__name__)

class SyncryptApp(object):
    '''
    The main controller class for Syncrypt commands. It can orchestrate
    multiple vaults and report status via a HTTP interface.
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
            username, password = yield from self.auth_provider.get_auth(vault.backend)
            vault.set_auth(username, password)
            yield from vault.backend.init()
            yield from vault.backend.upload_identity(self.identity)

    @asyncio.coroutine
    def upload_identity(self):
        backend = yield from self.open_backend()
        description = socket.gethostname()
        yield from backend.upload_identity(self.identity, description)
        logger.info('Uploaded public key with fingerprint "{0}".'.format(
            format_fingerprint(self.identity.get_fingerprint())))
        yield from backend.close()

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
            self.watchdogs[vault.folder] = create_watchdog(self, vault)
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
    def clone_local(self, clone_target):
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
    def list_vaults(self):
        backend = yield from self.open_backend()
        for vault in (yield from backend.list_vaults()):
            print("{0}".format(vault['id'].decode('utf-8')))
        yield from backend.close()

    @asyncio.coroutine
    def list_keys(self, user=None, with_art=False):
        backend = yield from self.open_backend()
        key_list = (yield from backend.list_keys(user))
        self.print_key_list(key_list, with_art=with_art)
        yield from backend.close()

    def print_key_list(self, key_list, with_art=False):
        for key in key_list:
            fingerprint = key['fingerprint']
            description = key['description'].decode()
            created_at = key['created_at']
            if with_art:
                print(draw_art(None, '1', fingerprint))
            print("{0:24}\t{1}\t{2}".format(format_fingerprint(fingerprint), description, created_at))

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
    def open_backend(self, always_ask_for_creds=False):
        'open a backend connection that will be independent from any vault'

        cfg = self.config
        backend = cfg.backend_cls(**cfg.backend_kwargs)
        for try_num in range(3):
            if always_ask_for_creds or try_num >= 1:
                username, password = yield from self.auth_provider.get_auth(backend)
                backend.username = username
                backend.password = password
                backend.auth = None
            try:
                yield from backend.open()
                if backend.auth and not 'auth' in cfg.remote:
                    cfg.update('remote', {'auth': backend.auth})
                    cfg.write(cfg.config_file)
            except StorageBackendInvalidAuth:
                logger.error('Invalid login')
                continue
            break
        return backend

    @asyncio.coroutine
    def clone(self, vault_id, local_directory):
        backend = yield from self.open_backend()

        logger.info('Retrieving encrypted key for vault %s (Fingerprint: %s)',
                vault_id, format_fingerprint(self.identity.get_fingerprint()))
        auth_token, package_info = yield from \
                backend.get_user_vault_key(self.identity.get_fingerprint(), vault_id)

        # decrypt package
        export_pipe = Once(package_info) \
            >> DecryptRSA_PKCS1_OAEP(self.identity.private_key)

        decrypted_package_info = yield from export_pipe.readall()

        vault = Vault.from_package_info(decrypted_package_info, local_directory, auth_token)

        self.add_vault(vault)

        yield from backend.close()

        yield from self.pull_vault(vault)


    @asyncio.coroutine
    def export(self, filename):
        vault = self.vaults[0]
        export_pipe = vault.package_info()
        if filename is None:
            export_pipe = export_pipe >> StdoutWriter()
        else:
            export_pipe = export_pipe >> FileWriter(filename)
        yield from export_pipe.consume()
        if filename:
            logger.info("Vault export has been written to: %s" % filename)

    @asyncio.coroutine
    def login(self):
        backend = yield from self.open_backend(always_ask_for_creds=True)
        logger.info('Successfully logged in and stored auth token.')
        yield from backend.close()
        yield from self.upload_identity()

    @asyncio.coroutine
    def add_user(self, email):
        vault = self.vaults[0]
        yield from vault.backend.open()
        logger.info('Adding user "%s" to %s', email, vault)
        yield from vault.backend.add_vault_user(email)

        key_list = yield from vault.backend.list_keys(email)
        key_list = list(key_list)

        self.print_key_list(key_list)
        print('\nPlease verify the above keys.')
        yesno = input('Do you really want to send the keys to all of the fingerprints listed above? [y/N] ')

        if yesno in ('y', 'Y'):
            for key in key_list:
                # retrieve key and verify fingerrint
                fingerprint = key['fingerprint']
                identity = Identity.from_public_key(key['public_key'], vault.config)
                assert identity.get_fingerprint() == fingerprint

                # construct and encrypt package
                export_pipe = vault.package_info() \
                    >> EncryptRSA_PKCS1_OAEP(identity.public_key)
                content = yield from export_pipe.readall()

                logger.info('Uploading vault package for %s/%s', email,
                        format_fingerprint(fingerprint))
                logger.debug('Package length is: %d', len(content))

                yield from vault.backend.add_user_vault_key(email, fingerprint, content)

    @asyncio.coroutine
    def print_log(self, verbose=False):
        local_tz = get_localzone()
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
                rev_id = server_info['id'].decode(vault.config.encoding)
                created_at = iso8601.parse_date(server_info['created_at'].decode())\
                        .astimezone(local_tz)\
                        .strftime('%x %X')
                operation = server_info['operation'].decode(vault.config.encoding)
                if verbose:
                    print("%s | %s | %-9s %s" % (created_at, rev_id,
                        operation, bundle.relpath))
                else:
                    print("%s | %-9s %s" % (created_at, operation, bundle.relpath))

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
        for vault in self.vaults:
            yield from self.pull_vault(vault)

    @asyncio.coroutine
    def pull_vault(self, vault):
        # TODO: do a change detection (.vault/metadata store vs filesystem)
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
            if 'id' in server_info:
                vault.update_revision(server_info['id'])
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
