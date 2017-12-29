import asyncio
import logging
import os.path
import socket
import sys
from distutils.version import LooseVersion
from io import StringIO
from zipfile import ZipFile

import iso8601
from tenacity import retry, stop_after_attempt, wait_exponential
from tzlocal import get_localzone

import syncrypt
from syncrypt.backends.base import StorageBackendInvalidAuth
from syncrypt.backends.binary import BinaryStorageBackend, ServerError
from syncrypt.exceptions import VaultFolderDoesNotExist, VaultNotInitialized
from syncrypt.models import Identity, Vault, VaultState, VirtualBundle
from syncrypt.pipes import (DecryptRSA_PKCS1_OAEP, EncryptRSA_PKCS1_OAEP,
                            FileWriter, Once, SnappyCompress, StdoutWriter)
from syncrypt.utils.format import (format_fingerprint, format_size,
                                   size_with_unit)
from syncrypt.utils.semaphores import JoinableSemaphore, JoinableSetSemaphore

from .asynccontext import AsyncContext
from .events import create_watchdog

logger = logging.getLogger(__name__)


class SyncryptApp(object):
    '''
    The main controller class for Syncrypt commands. A single instance of this class can
    orchestrate multiple vaults.
    '''

    def __init__(self, config, auth_provider=None, vault_dirs=None):
        self.auth_provider = auth_provider
        self.vaults = []
        self.config = config
        self.concurrency = int(self.config.app['concurrency'])

        # These enforce global limits on various bundle actions
        self.semaphores = {
            'update': JoinableSetSemaphore(8),
            'stat': JoinableSetSemaphore(8),
            'upload': JoinableSetSemaphore(8),
            'download': JoinableSetSemaphore(8)
        }

        self.stats = {
            'uploads': 0,
            'downloads': 0,
            'stats': 0
        }

        # A map from Bundle -> Future that contains all bundles scheduled for a push
        self._scheduled_pushes = {}

        # A map from Bundle -> Task that contains all running pushes
        self._running_pushes = {}

        # A map from Bundle -> Exception that contains all failed pushes
        self._failed_pushes = {}

        # This semaphore enforces the global concurrency limit for both pushes and pulls.
        self._bundle_actions = JoinableSemaphore(self.concurrency)

        # A map from folder -> Watchdog. Used by the daemon and the "watch" command.
        self._watchdogs = {}

        # A map from folder -> Task. Used by the daemon to autopull vault periodically.
        self._autopull_tasks = {}

        def handler(loop, **kwargs):
            if 'exception' in kwargs and isinstance(kwargs['exception'], asyncio.CancelledError):
                return
            logger.error("Exception in event loop: %s, %s", args, kwargs)
        asyncio.get_event_loop().set_exception_handler(handler)

        # generate or read users identity
        id_rsa_path = os.path.join(self.config.config_dir, 'id_rsa')
        id_rsa_pub_path = os.path.join(self.config.config_dir, 'id_rsa.pub')
        self.identity = Identity(id_rsa_path, id_rsa_pub_path, self.config)

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

    @asyncio.coroutine
    def initialize(self):
        yield from self.identity.init()

    def add_vault_by_path(self, path):
        return self.add_vault(Vault(path))

    def add_vault(self, vault):
        self.vaults.append(vault)
        with self.config.update_context():
            self.config.add_vault_dir(os.path.abspath(vault.folder))
        return vault

    def find_vault_by_id(self, vault_id):
        for v in self.vaults:
            if str(v.config.get('vault.id')) == vault_id:
                return v
        raise ValueError('Vault not found: {}'.format(vault_id))

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

    @asyncio.coroutine
    def delete_vaults(self):
        for vault in self.vaults:
            yield from self.delete_vault(vault)

    def cancel_push(self, bundle):
        if bundle in self._scheduled_pushes:
            self._scheduled_pushes[bundle].cancel()
            del self._scheduled_pushes[bundle]
        if bundle in self._running_pushes:
            logger.warn('Update/upload for %s is running, aborting it now.', bundle)
            self._running_pushes[bundle].cancel()
            del self._running_pushes[bundle]

    def schedule_push(self, bundle):
        self.cancel_push(bundle)
        loop = asyncio.get_event_loop()
        logger.debug('Scheduling update for %s', bundle)

        def push_scheduled(bundle):
            del self._scheduled_pushes[bundle]
            logger.debug('Scheduled update is executing for %s', bundle)
            asyncio.ensure_future(self.push_bundle(bundle))

        self._scheduled_pushes[bundle] = loop.call_later(1.0, push_scheduled, bundle)

    @asyncio.coroutine
    def init_vault(self, vault, host=None, upload_vault_key=True, upload_identity=True):
        if host:
            # If host was explicitly given, use it
            vault.config.set('remote.host', host)
            vault.backend.host = host
        else:
            # otherwise, use host from global config
            vault.config.set('remote.host', self.config.get('remote.host'))
            vault.backend.host = self.config.get('remote.host')

        try:
            yield from vault.backend.open()
            logger.warn('Vault %s already initialized', vault.folder)
            return
        except (StorageBackendInvalidAuth, VaultNotInitialized):
            pass
        logger.info("Initializing %s", vault)
        yield from vault.identity.init()
        global_auth = self.config.remote.get('auth')
        if global_auth:
            logger.debug('Using user auth token to initialize vault.')
            vault.backend.global_auth = global_auth
        try:
            yield from vault.backend.init()
        except StorageBackendInvalidAuth:
            vault.backend.global_auth = None
            username, password = yield from self.auth_provider.get_auth(vault.backend)
            vault.backend.set_auth(username, password)
            yield from vault.backend.init()

        with vault.config.update_context():
            vault.config.set('vault.name', os.path.basename(os.path.abspath(vault.folder)))
        yield from vault.backend.set_vault_metadata()
        if upload_identity:
            yield from vault.backend.upload_identity(self.identity)
        if upload_vault_key:
            yield from self.upload_vault_key(vault)

    @asyncio.coroutine
    def init(self, **kwargs):
        for vault in self.vaults:
            yield from self.init_vault(vault, **kwargs)

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
            yield from self.init_vault(vault, host=self.config.remote.get('host'))
            yield from vault.backend.open()

    async def set_vault_state(self, vault, new_state):
        if vault.state != new_state:
            old_state = vault.state
            vault.state = new_state
            await self.handle_state_transition(vault, old_state)

    async def handle_state_transition(self, vault, old_state):
        logger.info('STATE TRANSITION %s -> %s', vault, vault.state)
        new_state = vault.state

        if new_state in (VaultState.READY,):
            await self.watch_vault(vault)
        else:
            if old_state in (VaultState.READY,):
                await self.unwatch_vault(vault)

        #if new_state == VaultState.SYNCED:
        #    await self.autopull_vault(vault)
        #elif old_state == VaultState.SYNCED:
        #    await self.unautopull_vault(vault)

    @asyncio.coroutine
    def watch_vault(self, vault):
        'Install a watchdog for the given vault'
        vault.check_existence()
        folder = os.path.abspath(vault.folder)
        logger.info('Watching %s', folder)
        self._watchdogs[folder] = create_watchdog(self, vault)
        self._watchdogs[folder].start()

    @asyncio.coroutine
    def autopull_vault(self, vault):
        'Install a regular autopull for the given vault'
        vault.check_existence()
        folder = os.path.abspath(vault.folder)
        logger.info('Auto-pulling %s every %d seconds', folder, int(vault.config.get('vault.pull_interval')))
        self._autopull_tasks[folder] = asyncio.Task(self.pull_vault_periodically(vault))

    @asyncio.coroutine
    def unwatch_vault(self, vault):
        'Remove watchdog and auto-pulls'
        folder = os.path.abspath(vault.folder)
        logger.info('Unwatching %s', os.path.abspath(folder))
        if folder in self._watchdogs:
            self._watchdogs[folder].stop()
            del self._watchdogs[folder]

    @asyncio.coroutine
    def unautopull_vault(self, vault):
        folder = os.path.abspath(vault.folder)
        logger.info('Disable auto-pull on %s', os.path.abspath(folder))
        if folder in self._autopull_tasks:
            self._autopull_tasks[folder].cancel()
            del self._autopull_tasks[folder]

    @asyncio.coroutine
    def push_bundle(self, bundle):
        yield from self._bundle_actions.acquire()
        task = asyncio.get_event_loop().create_task(self._push_bundle(bundle))

        def cb(_task):
            if bundle in self._running_pushes:
                del self._running_pushes[bundle]

            if _task.cancelled():
                logger.info("Upload of %s got canceled.", bundle)

            if task.exception():
                ex = task.exception()

                #from traceback import format_tb
                logger.exception(ex)
                #"Got exception: %s %s %s", ex, type(ex),
                #        format_tb(ex.__traceback__))
                self._failed_pushes[bundle] = ex

            asyncio.get_event_loop().create_task(self._bundle_actions.release())

        self._running_pushes[bundle] = task
        task.add_done_callback(cb)

    @asyncio.coroutine
    def pull_bundle(self, bundle):
        yield from self._bundle_actions.acquire()
        task = asyncio.get_event_loop().create_task(self._pull_bundle(bundle))
        def cb(_task):
            if task.exception():
                from traceback import format_tb
                ex = task.exception()
                logger.warn("Got exception: %s %s %s", ex, type(ex),
                        format_tb(ex.__traceback__))
            asyncio.get_event_loop().create_task(self._bundle_actions.release())
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
                if not auth_provider:
                    raise ValueError('Can not login, do not have auth provider')
                username, password = yield from auth_provider.get_auth(backend)
                backend.set_auth(username, password)
                backend.auth = None
            try:
                if not backend.global_auth:
                    backend.global_auth = cfg.get('remote.auth')
                yield from backend.open()
                if backend.global_auth and backend.global_auth != cfg.get('remote.auth'):
                    logger.info('Updating global auth token')
                    with cfg.update_context():
                        cfg.update('remote', {'auth': backend.global_auth})
                return backend
            except StorageBackendInvalidAuth as e:
                logger.error('Invalid login: %s' % e)
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
    def import_package(self, filename, target_folder, pull_vault=False):
        if os.path.exists(target_folder):
            raise ValueError('Folder "{0}" already exists.'.format(target_folder))

        with ZipFile(filename, 'r') as myzip:
            myzip.extractall(target_folder)

        logger.info('Imported vault into "%s"', target_folder)

        vault = Vault(target_folder)
        yield from self.open_or_init(vault)

        if pull_vault:
            yield from self.pull_vault(vault)
        return vault

    @asyncio.coroutine
    def export_package(self, filename, vault=None):
        if vault is None:
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
        yield from backend.close()
        yield from self.upload_identity()

    @asyncio.coroutine
    def add_user_vault_key(self, vault, email, identity):
        # construct and encrypt package
        export_pipe = vault.package_info() \
            >> EncryptRSA_PKCS1_OAEP(identity.public_key)
        content = yield from export_pipe.readall()

        logger.info('Uploading vault package for %s/%s', email,
                format_fingerprint(identity.get_fingerprint()))
        logger.debug('Package length is: %d', len(content))

        yield from vault.backend.add_user_vault_key(email, identity.get_fingerprint(), content)

    @asyncio.coroutine
    def upload_vault_key(self, vault=None):
        if vault is None:
            vault = self.vaults[0]
        yield from vault.backend.open()
        user_info = yield from vault.backend.user_info()
        email = user_info['email']
        yield from self.add_user_vault_key(vault, email, self.identity)

    @asyncio.coroutine
    def get_remote_size_for_vault(self, vault):
        yield from vault.backend.open()
        return (yield from vault.backend.vault_size(vault))

    @asyncio.coroutine
    def retrieve_metadata(self, vault):
        yield from vault.backend.open()
        return (yield from vault.backend.vault_metadata())

    #@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
    @asyncio.coroutine
    def push(self):
        "Push all registered vaults"
        with AsyncContext() as ctx:
            for vault in self.vaults:

                if vault.state != VaultState.READY:
                    logger.warning("Skipping %s because it state is %s", vault, vault.state)

                yield from ctx.create_task(vault, self.push_vault(vault))
                #try:
                    #logger.info('Pushing %s', vault)
                    #yield from vault.backend.open()
                    #yield from vault.backend.set_vault_metadata()

                    #for bundle in vault.walk_disk():
                    #    yield from ctx.create_task(bundle, self._push_bundle(bundle))
                #except VaultNotInitialized:
                #    logger.error('%s has not been initialized. Use "syncrypt init" to register the folder as vault.' % vault)
                #    continue
                #except VaultFolderDoesNotExist:
                #    logger.error('%s does not exist, removing vault from list.' % vault)
                #    yield from self.remove_vault(vault)
                #   continue
            result = yield from ctx.wait()
        print(result)

    #@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
    @asyncio.coroutine
    def push_vault(self, vault):
        "Push a single vault"
        logger.info('Pushing %s', vault)
        with AsyncContext() as ctx:
            yield from vault.backend.open()
            yield from vault.backend.set_vault_metadata()
            for bundle in vault.walk_disk():
                yield from ctx.create_task(bundle, self._push_bundle(bundle))
            yield from ctx.wait()

    @asyncio.coroutine
    def pull(self, full=False):
        "Pull all registered vaults"
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
                print("EXCEPTION")
                logger.exception(e)
                continue
        yield from self.wait()

    @asyncio.coroutine
    def pull_vault_periodically(self, vault):
        while True:
            yield from asyncio.sleep(int(vault.config.get('vault.pull_interval')))
            yield from self.pull_vault(vault)

    @asyncio.coroutine
    def pull_vault(self, vault, full=False):
        vault.logger.info('Pulling %s', vault)
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
            try:
                bundle = yield from vault.add_bundle_by_metadata(store_hash, metadata)
                task = yield from self.pull_bundle(bundle)
                task.add_done_callback(cb)
            except Exception as e:
                vault.logger.exception(e)
            latest_revision = server_info.get('id') or latest_revision
        yield from self.wait()

        success = len(successful) == total

        if success:
            if total == 0:
                vault.logger.info('No changes in %s', vault)
            else:
                vault.logger.info('Successfully pulled %d revisions for %s', total, vault)
                if latest_revision:
                    vault.update_revision(latest_revision)
        else:
            vault.logger.error('%s failure(s) occured while pulling %d revisions for %s',
                    total - len(successful), total, vault)

    @asyncio.coroutine
    def wait(self):
        yield from self._bundle_actions.join()

    @asyncio.coroutine
    def close(self):
        yield from self.wait()
        for vault in self.vaults:
            yield from vault.close()

    #@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
    @asyncio.coroutine
    def _push_bundle(self, bundle):
        'update bundle and maybe upload'

        yield from self.semaphores['update'].acquire(bundle)
        yield from bundle.update()
        yield from self.semaphores['update'].release(bundle)

        yield from self.semaphores['stat'].acquire(bundle)
        yield from bundle.vault.backend.stat(bundle)
        self.stats['stats'] += 1
        yield from self.semaphores['stat'].release(bundle)
        if bundle.remote_hash_differs:
            yield from self.semaphores['upload'].acquire(bundle)
            yield from bundle.vault.backend.upload(bundle)
            self.stats['uploads'] += 1
            yield from self.semaphores['upload'].release(bundle)

    @asyncio.coroutine
    def _pull_bundle(self, bundle):
        'update, maybe download, and then decrypt'
        yield from self.semaphores['update'].acquire(self)
        yield from bundle.update()
        yield from self.semaphores['update'].release(self)
        yield from self.semaphores['stat'].acquire(bundle)
        yield from bundle.vault.backend.stat(bundle)
        self.stats['stats'] += 1
        yield from self.semaphores['stat'].release(bundle)
        if bundle.remote_crypt_hash is None:
            logger.warn('File not found: %s', bundle)
            return
        if bundle.remote_hash_differs:
            yield from self.semaphores['download'].acquire(bundle)
            yield from bundle.vault.backend.download(bundle)
            self.stats['downloads'] += 1
            yield from self.semaphores['download'].release(bundle)
