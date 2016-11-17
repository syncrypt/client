import logging
import os.path
import socket
import sys
import asyncio
import iso8601
from io import StringIO

import syncrypt
from syncrypt.backends.base import StorageBackendInvalidAuth
from syncrypt.backends.binary import BinaryStorageBackend, ServerError
from syncrypt.exceptions import VaultNotInitialized, VaultFolderDoesNotExist
from syncrypt.models import Identity, Vault, VirtualBundle
from syncrypt.pipes import (DecryptRSA_PKCS1_OAEP, EncryptRSA_PKCS1_OAEP,
                            FileWriter, Once, SnappyCompress, StdoutWriter)
from syncrypt.utils.format import format_fingerprint, format_size, size_with_unit
from syncrypt.utils.semaphores import JoinableSemaphore
from syncrypt.vendor.keyart import draw_art
from tzlocal import get_localzone

from syncrypt.api import SyncryptAPI

from .events import create_watchdog
from ..utils.updates import is_update_available

logger = logging.getLogger(__name__)

class SyncryptApp(object):
    '''
    The main controller class for Syncrypt commands. It can orchestrate
    multiple vaults and report status via a HTTP interface.
    '''

    def __init__(self, config, auth_provider=None, vault_dirs=None):
        self.auth_provider = auth_provider
        self.vaults = []

        # map from Bundle -> Future
        self.update_handles = {}

        self.config = config
        self.concurrency = int(self.config.app['concurrency'])
        self.bundle_action_semaphore = JoinableSemaphore(self.concurrency)
        self.watchdogs = {}
        self.pull_tasks = {}
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
        if vault_dirs is None:
            vault_dirs = self.config.vault_dirs
        for vault_dir in vault_dirs:
            vault = Vault(vault_dir)
            try:
                vault.check_existence()
                self.vaults.append(vault)
            except VaultFolderDoesNotExist:
                logger.warn('Ignoring %s, because its folder does not exist', vault)

        super(SyncryptApp, self).__init__()

    def add_vault_by_path(self, path):
        return self.add_vault(Vault(path))

    def add_vault(self, vault):
        self.vaults.append(vault)
        with self.config.update_context():
            self.config.add_vault_dir(os.path.abspath(vault.folder))
        return vault

    @asyncio.coroutine
    def remove_vault(self, vault):
        with self.config.update_context():
            self.config.remove_vault_dir(os.path.abspath(vault.folder))
        self.vaults.remove(vault)

    @asyncio.coroutine
    def delete_vault(self, vault):
        yield from vault.backend.open()
        yield from vault.backend.delete_vault()
        yield from self.remove_vault(vault)

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
    def check_update(self):
        logger.debug('Retrieving available version...')
        can_update, available = yield from is_update_available()
        print('Installed:   {0}'.format(syncrypt.__version__))
        print('Available:   {0}'.format(available))
        if can_update:
            print('\nAn update to version {0} is available, please download it at'.format(available))
            print('\thttp://alpha.syncrypt.space/releases/')
        else:
            print('\nYou are up to date.')

    @asyncio.coroutine
    def init(self, vault=None, host=None):
        for vault in (self.vaults if vault is None else [vault]):

            if host:
                # If host was explicitly given, use it
                vault.config.set('remote.host', host)
            else:
                # otherwise, use host from global config
                vault.config.set('remote.host', self.config.get('remote.host'))

            try:
                yield from vault.backend.open()
                logger.warn('Vault %s already initialized', vault.folder)
                continue
            except (StorageBackendInvalidAuth, VaultNotInitialized):
                pass
            logger.info("Initializing %s", vault)
            vault.identity.init()
            global_auth = self.config.remote.get('auth')
            if global_auth:
                logger.debug('Using user auth token to initialize vault.')
                vault.set_global_auth(global_auth)
            try:
                yield from vault.backend.init()
            except StorageBackendInvalidAuth:
                username, password = yield from self.auth_provider.get_auth(vault.backend)
                vault.set_auth(username, password)
                try:
                    yield from vault.backend.init()
                except StorageBackendInvalidAuth:
                    logger.error('Invalid authentification')
                    continue
            with vault.config.update_context():
                vault.config.set('vault.name', os.path.basename(os.path.abspath(vault.folder)))
            yield from vault.backend.set_vault_metadata()
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
        except (StorageBackendInvalidAuth, VaultNotInitialized):
            # retry after logging in & getting auth token
            # use the host from the app config
            yield from self.init(vault, host=self.config.remote.get('host'))
            yield from vault.backend.open()

    @asyncio.coroutine
    def start(self):
        yield from self.api.start()
        yield from self.push()
        for vault in self.vaults:
            try:
                yield from self.watch(vault)
                yield from self.autopull_vault(vault)
            except VaultFolderDoesNotExist:
                logger.error('%s does not exist, removing vault from list.' % vault)
                yield from self.remove_vault(vault)

    @asyncio.coroutine
    def watch(self, vault):
        'Install a watchdog and auto-pull for vault'
        vault.check_existence()
        folder = os.path.abspath(vault.folder)
        logger.info('Watching %s', folder)
        self.watchdogs[folder] = create_watchdog(self, vault)
        self.watchdogs[folder].start()

    @asyncio.coroutine
    def autopull_vault(self, vault):
        vault.check_existence()
        folder = os.path.abspath(vault.folder)
        logger.info('Auto-pulling %s every %d seconds', folder, int(vault.config.get('vault.pull_interval')))
        self.pull_tasks[folder] = asyncio.Task(self.pull_vault_periodically(vault))

    @asyncio.coroutine
    def unwatch_vault(self, vault):
        'Remove watchdog and auto-pulls'
        folder = os.path.abspath(vault.folder)
        logger.info('Unwatching %s', os.path.abspath(folder))
        if folder in self.watchdogs:
            self.watchdogs[folder].stop()
            del self.watchdogs[folder]

    @asyncio.coroutine
    def unautopull_vault(self, vault):
        folder = os.path.abspath(vault.folder)
        logger.info('Disable auto-pull on %s', os.path.abspath(folder))
        if folder in self.pull_tasks:
            self.pull_tasks[folder].cancel()
            del self.pull_tasks[folder]

    @asyncio.coroutine
    def stop(self):
        for vault in self.vaults:
            yield from self.unwatch_vault(vault)
            yield from self.unautopull_vault(vault)
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
        return task

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
    def list_all_vaults(self):
        backend = yield from self.open_backend()
        for vault in (yield from backend.list_vaults()):
            logger.debug("Received vault: %s", vault)
            size, size_unit = size_with_unit(vault['byte_size'])
            fmt_str = "{0} | Users: {1:2} | Files: {2:4} | Revisions: {3:4} | Size: {4:8} {5}".format(
                vault['id'].decode('utf-8'),
                vault['user_count'],
                vault['file_count'],
                vault['revision_count'],
                size,
                size_unit
            )
            print(fmt_str)
        yield from backend.close()

    @asyncio.coroutine
    def _list_vaults_with_name(self):
        logger.debug('Retrieving vault list...')
        backend = yield from self.open_backend()
        my_fingerprint = self.identity.get_fingerprint()
        vaults = []

        for (vault, user_vault_key, encrypted_metadata) in \
                    (yield from backend.list_vaults_by_fingerprint(my_fingerprint)):

            vault_id = vault['id'].decode('utf-8')

            logger.debug("Received vault: %s (with%s metadata)", vault_id, '' if encrypted_metadata else 'out')

            name = ""
            if encrypted_metadata:
                metadata = yield from self._decrypt_metadata(encrypted_metadata, user_vault_key)
                if 'name' in metadata:
                    name = metadata['name']

            vaults.append((vault_id, name))

        yield from backend.close()

        return vaults

    @asyncio.coroutine
    def list_vaults(self):
        for (vault_id, name) in (yield from self._list_vaults_with_name()):
            print("{0} {1}".format(vault_id, name))

    @asyncio.coroutine
    def _decrypt_metadata(self, encrypted_metadata, user_vault_key):
        import zipfile
        from io import BytesIO
        from syncrypt.pipes import SnappyDecompress
        import umsgpack

        # decrypt package
        export_pipe = Once(user_vault_key) \
            >> DecryptRSA_PKCS1_OAEP(self.identity.private_key)

        package_info = yield from export_pipe.readall()


        zipf = zipfile.ZipFile(BytesIO(package_info), 'r')

        vault_public_key = zipf.read('.vault/id_rsa.pub')
        vault_key = zipf.read('.vault/id_rsa')

        vault_identity = Identity.from_key(vault_public_key, self.config, private_key=vault_key)

        sink = Once(encrypted_metadata) \
                >> DecryptRSA_PKCS1_OAEP(vault_identity.private_key) \
                >> SnappyDecompress()

        serialized_metadata = metadata = yield from sink.readall()
        return umsgpack.unpackb(serialized_metadata)

    @asyncio.coroutine
    def list_keys(self, user=None, with_art=False):
        backend = yield from self.open_backend()
        key_list = (yield from backend.list_keys(user))
        self.print_key_list(key_list, with_art=with_art)
        yield from backend.close()

    def print_key_list(self, key_list, with_art=False):
        for key in key_list:
            fingerprint = key['fingerprint']
            description = key['description']
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

    @asyncio.coroutine
    def set(self, setting, value):
        for vault in self.vaults:
            with vault.config.update_context():
                vault.config.set(setting, value)

    @asyncio.coroutine
    def unset(self, setting):
        for vault in self.vaults:
            with vault.config.update_context():
                vault.config.unset(setting)

    @asyncio.coroutine
    def open_backend(self, always_ask_for_creds=False, auth_provider=None, num_tries=3):
        'open a backend connection that will be independent from any vault'

        cfg = self.config
        auth_provider = auth_provider or self.auth_provider
        backend = cfg.backend_cls(**cfg.backend_kwargs)
        for try_num in range(num_tries):
            if always_ask_for_creds or try_num >= 1:
                username, password = yield from auth_provider.get_auth(backend)
                backend.username = username
                backend.password = password
                backend.auth = None
            try:
                yield from backend.open()
                if backend.auth:
                    with cfg.update_context():
                        cfg.update('remote', {'auth': backend.auth})
                return backend
            except StorageBackendInvalidAuth:
                logger.error('Invalid login')
                if (try_num + 1) < num_tries:
                    continue
                else:
                    raise

    @asyncio.coroutine
    def clone(self, vault_id, local_directory):
        backend = yield from self.open_backend()

        logger.info('Retrieving encrypted key for vault %s (Fingerprint: %s)',
                vault_id, format_fingerprint(self.identity.get_fingerprint()))
        auth_token, package_info = yield from \
                backend.get_user_vault_key(self.identity.get_fingerprint(), vault_id)

        yield from backend.close()

        # decrypt package
        export_pipe = Once(package_info) \
            >> DecryptRSA_PKCS1_OAEP(self.identity.private_key)

        decrypted_package_info = yield from export_pipe.readall()

        vault = Vault.from_package_info(decrypted_package_info, local_directory, auth_token)

        self.add_vault(vault)

        yield from self.retrieve_metadata(vault)

        return vault

    @asyncio.coroutine
    def clone_by_name(self, vault_name, local_directory):

        logger.info('Trying to find vault with name "%s"...', vault_name)
        vault_id = None
        for (vid, name) in (yield from self._list_vaults_with_name()):
            vault_id = vid
            if name == vault_name:
                break
            vault_id = None

        if vault_id:
            vault = yield from self.clone(vault_id, local_directory)
        else:
            logger.error('No vault found with name "%s"', vault_name)
            vault = None

        return vault


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
                public_key = key['public_key']
                yield from self.add_user_vault_key(vault, email, fingerprint, public_key)

    @asyncio.coroutine
    def add_user_vault_key(self, vault, email, fingerprint, public_key):
        identity = Identity.from_key(public_key, vault.config)
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
            try:
                yield from vault.backend.open()
            except VaultNotInitialized:
                logger.error('%s has not been initialized. Use "syncrypt init" to register the folder as vault.' % vault)
                continue
            queue = yield from vault.backend.changes(None, None, verbose=verbose)
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
                    user_email = server_info['email'].decode(vault.config.encoding)
                    print("%s | %s | %s | %-9s %s" % (created_at, rev_id, user_email,
                        operation, bundle.relpath))
                else:
                    print("%s | %-9s %s" % (created_at, operation, bundle.relpath))

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
    def push(self):
        '''
        Push all vaults

        High level command that will catch exceptions and log errors
        '''
        for vault in self.vaults:
            try:
                yield from self.push_vault(vault)
            except VaultNotInitialized:
                logger.error('%s has not been initialized. Use "syncrypt init" to register the folder as vault.' % vault)
                continue
            except VaultFolderDoesNotExist:
                logger.error('%s does not exist, removing vault from list.' % vault)
                yield from self.remove_vault(vault)
                continue
            except Exception as e:
                import ipdb; ipdb.set_trace()
                logger.exception(e)
                continue
        yield from self.wait()

    @asyncio.coroutine
    def pull(self, full=False):
        '''
        Pull all vaults

        High level command that will catch exceptions and log errors
        '''
        for vault in self.vaults:
            try:
                yield from self.pull_vault(vault, full=full)
            except VaultNotInitialized:
                logger.error('%s has not been initialized. Use "syncrypt init" to register the folder as vault.' % vault)
                continue
            except VaultFolderDoesNotExist:
                logger.error('%s does not exist, removing vault from list.' % vault)
                yield from this.remove_vault(vault)
                continue
            except Exception as e:
                logger.exception(e)
                continue
        yield from self.wait()

    @asyncio.coroutine
    def push_vault(self, vault):
        logger.info('Pushing %s', vault)
        yield from vault.backend.open()
        yield from vault.backend.set_vault_metadata()
        for bundle in vault.walk_disk():
            yield from self.push_bundle(bundle)

    @asyncio.coroutine
    def pull_vault_periodically(self, vault):
        while True:
            yield from asyncio.sleep(int(vault.config.get('vault.pull_interval')))
            # Disable watch during periodic pulls
            yield from self.unwatch_vault(vault)
            yield from self.pull_vault(vault)
            yield from self.watch(vault)

    @asyncio.coroutine
    def pull_vault(self, vault, full=False):
        logger.info('Pulling %s', vault)
        latest_revision = None
        total = 0
        successful = []

        def cb(_task):
            if not _task.exception():
                successful.append(_task)

        yield from self.retrieve_metadata(vault)

        # TODO: do a change detection (.vault/metadata store vs filesystem)
        yield from self.open_or_init(vault)
        if not vault.revision or full:
            queue = yield from vault.backend.list_files()
        else:
            queue = yield from vault.backend.changes(vault.revision, None)
        while True:
            item = yield from queue.get()
            if item is None:
                break
            total += 1
            store_hash, metadata, server_info = item
            bundle = yield from vault.add_bundle_by_metadata(store_hash, metadata)
            task = yield from self.pull_bundle(bundle)
            task.add_done_callback(cb)
            latest_revision = server_info.get('id') or latest_revision
        yield from self.wait()

        success = len(successful) == total

        if success:
            if total == 0:
                logger.info('No changes in %s', vault)
            else:
                logger.info('Successfully pulled %d revisions for %s', total, vault)
                if latest_revision:
                    vault.update_revision(latest_revision)
        else:
            logger.error('%s failures occured while pulling %d revisions for %s',
                    total - len(successful), total, vault)

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
