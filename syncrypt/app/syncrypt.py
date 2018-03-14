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

        def handler(loop, args, **kwargs):
            if 'exception' in kwargs and isinstance(kwargs['exception'], asyncio.CancelledError):
                return
            logger.error("Unhandled exception in event loop: %s, %s", args, kwargs)
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

    async def initialize(self):
        await self.identity.init()

    def add_vault_by_path(self, path):
        return self.add_vault(Vault(path))

    def add_vault(self, vault):
        self.vaults.append(vault)
        with self.config.update_context():
            self.config.add_vault_dir(os.path.abspath(vault.folder))
        return vault

    def find_vault_by_id(self, vault_id):
        for v in self.vaults:
            if v.id == vault_id:
                return v
        raise ValueError('Vault not found: {}'.format(vault_id))

    async def remove_vault(self, vault):
        with self.config.update_context():
            self.config.remove_vault_dir(os.path.abspath(vault.folder))
        self.vaults.remove(vault)

    async def delete_vault(self, vault):
        await vault.backend.open()
        await vault.backend.delete_vault()
        await self.remove_vault(vault)

    async def delete_vaults(self):
        for vault in self.vaults:
            await self.delete_vault(vault)

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

    async def init_vault(self, vault, host=None, upload_vault_key=True, upload_identity=True):
        if host:
            # If host was explicitly given, use it
            vault.config.set('remote.host', host)
            vault.backend.host = host
        else:
            # otherwise, use host from global config
            vault.config.set('remote.host', self.config.get('remote.host'))
            vault.backend.host = self.config.get('remote.host')

        try:
            await vault.backend.open()
            logger.warn('Vault %s already initialized', vault.folder)
            return
        except (StorageBackendInvalidAuth, VaultNotInitialized):
            pass
        logger.info("Initializing %s", vault)
        await vault.identity.init()
        global_auth = self.config.remote.get('auth')
        if global_auth:
            logger.debug('Using user auth token to initialize vault.')
            vault.backend.global_auth = global_auth
        try:
            await vault.backend.init()
        except StorageBackendInvalidAuth:
            vault.backend.global_auth = None
            username, password = await self.auth_provider.get_auth(vault.backend)
            vault.backend.set_auth(username, password)
            await vault.backend.init()

        with vault.config.update_context():
            vault.config.set('vault.name', os.path.basename(os.path.abspath(vault.folder)))
        await vault.backend.set_vault_metadata()
        if upload_identity:
            await vault.backend.upload_identity(self.identity)
        if upload_vault_key:
            await self.upload_vault_key(vault)

    async def init(self, **kwargs):
        for vault in self.vaults:
            await self.init_vault(vault, **kwargs)

    async def upload_identity(self):
        backend = await self.open_backend()
        description = socket.gethostname()
        await backend.upload_identity(self.identity, description)
        logger.info('Uploaded public key with fingerprint "{0}".'.format(
            format_fingerprint(self.identity.get_fingerprint())))
        await backend.close()

    async def open_or_init(self, vault):
        try:
            await vault.backend.open()
        except (StorageBackendInvalidAuth, VaultNotInitialized):
            # retry after logging in & getting auth token
            # use the host from the app config
            await self.init_vault(vault, host=self.config.remote.get('host'))
            await vault.backend.open()

    async def set_vault_state(self, vault, new_state):
        if vault.state != new_state:
            old_state = vault.state
            vault.state = new_state
            await self.handle_state_transition(vault, old_state)

    async def handle_state_transition(self, vault, old_state):
        logger.debug('State transition of %s: %s -> %s', vault, old_state,
                     vault.state)
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

    async def watch_vault(self, vault):
        'Install a watchdog for the given vault'
        vault.check_existence()
        folder = os.path.abspath(vault.folder)
        logger.info('Watching %s', folder)
        self._watchdogs[folder] = create_watchdog(self, vault)
        self._watchdogs[folder].start()

    async def autopull_vault(self, vault):
        'Install a regular autopull for the given vault'
        vault.check_existence()
        folder = os.path.abspath(vault.folder)
        logger.info('Auto-pulling %s every %d seconds', folder, int(vault.config.get('vault.pull_interval')))
        self._autopull_tasks[folder] = asyncio.Task(self.pull_vault_periodically(vault))

    async def unwatch_vault(self, vault):
        'Remove watchdog and auto-pulls'
        folder = os.path.abspath(vault.folder)
        if folder in self._watchdogs:
            logger.info('Unwatching %s', os.path.abspath(folder))
            self._watchdogs[folder].stop()
            del self._watchdogs[folder]

    async def unautopull_vault(self, vault):
        folder = os.path.abspath(vault.folder)
        logger.info('Disable auto-pull on %s', os.path.abspath(folder))
        if folder in self._autopull_tasks:
            self._autopull_tasks[folder].cancel()
            del self._autopull_tasks[folder]

    async def clone_local(self, clone_target):
        import shutil
        import os

        vault = self.vaults[0]

        await self.push()

        if not os.path.exists(clone_target):
            os.makedirs(clone_target)

        vault_cfg = os.path.join(clone_target, '.vault')
        if not os.path.exists(vault_cfg):
            os.makedirs(vault_cfg)

        for f in ('config', 'id_rsa', 'id_rsa.pub'):
            shutil.copyfile(os.path.join(vault.folder, '.vault', f), os.path.join(vault_cfg, f))

        logger.info("Cloned %s to %s" % (vault.folder, os.path.abspath(clone_target)))

        self.add_vault(Vault(clone_target))

        await self.pull()

    async def _list_vaults_with_name(self):
        logger.debug('Retrieving vault list...')
        backend = await self.open_backend()
        my_fingerprint = self.identity.get_fingerprint()
        vaults = []

        for (vault, user_vault_key, encrypted_metadata) in \
                    (await backend.list_vaults_by_fingerprint(my_fingerprint)):

            vault_id = vault['id'].decode('utf-8')

            logger.debug("Received vault: %s (with%s metadata)", vault_id, '' if encrypted_metadata else 'out')

            name = ""
            if encrypted_metadata:
                metadata = await self._decrypt_metadata(encrypted_metadata, user_vault_key)
                if 'name' in metadata:
                    name = metadata['name']

            vaults.append((vault_id, name))

        await backend.close()

        return vaults

    async def _decrypt_metadata(self, encrypted_metadata, user_vault_key):
        import zipfile
        from io import BytesIO
        from syncrypt.pipes import SnappyDecompress
        import umsgpack

        # decrypt package
        export_pipe = Once(user_vault_key) \
            >> DecryptRSA_PKCS1_OAEP(self.identity.private_key)

        package_info = await export_pipe.readall()

        zipf = zipfile.ZipFile(BytesIO(package_info), 'r')

        vault_public_key = zipf.read('.vault/id_rsa.pub')
        vault_key = zipf.read('.vault/id_rsa')

        vault_identity = Identity.from_key(vault_public_key, self.config, private_key=vault_key)

        sink = Once(encrypted_metadata) \
                >> DecryptRSA_PKCS1_OAEP(vault_identity.private_key) \
                >> SnappyDecompress()

        serialized_metadata = metadata = await sink.readall()
        return umsgpack.unpackb(serialized_metadata)

    async def set(self, setting, value):
        for vault in self.vaults:
            with vault.config.update_context():
                vault.config.set(setting, value)

    async def unset(self, setting):
        for vault in self.vaults:
            with vault.config.update_context():
                vault.config.unset(setting)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
    async def check_vault(self, vault: Vault):
        await vault.backend.open()

    async def open_backend(self, always_ask_for_creds=False, auth_provider=None, num_tries=3):
        'open a backend connection that will be independent from any vault'

        cfg = self.config
        auth_provider = auth_provider or self.auth_provider
        backend = cfg.backend_cls(**cfg.backend_kwargs)
        for try_num in range(num_tries):
            if always_ask_for_creds or try_num >= 1:
                if not auth_provider:
                    raise ValueError('Can not login, do not have auth provider')
                username, password = await auth_provider.get_auth(backend)
                backend.set_auth(username, password)
                backend.auth = None
            try:
                if not backend.global_auth:
                    backend.global_auth = cfg.get('remote.auth')
                await backend.open()
                if backend.global_auth and backend.global_auth != cfg.get('remote.auth'):
                    logger.info('Updating global auth token')
                    with cfg.update_context():
                        cfg.update('remote', {'auth': backend.global_auth})
                return backend
            except StorageBackendInvalidAuth as e:
                if (try_num + 1) < num_tries:
                    logger.error('Invalid login: %s' % e)
                    continue
                else:
                    raise

    async def clone(self, vault_id, local_directory):
        backend = await self.open_backend()

        logger.info('Retrieving encrypted key for vault %s (Fingerprint: %s)',
                vault_id, format_fingerprint(self.identity.get_fingerprint()))
        auth_token, package_info = await \
                backend.get_user_vault_key(self.identity.get_fingerprint(), vault_id)

        await backend.close()

        # decrypt package
        export_pipe = Once(package_info) \
            >> DecryptRSA_PKCS1_OAEP(self.identity.private_key)

        decrypted_package_info = await export_pipe.readall()

        vault = Vault.from_package_info(decrypted_package_info, local_directory, auth_token)

        self.add_vault(vault)

        await self.retrieve_metadata(vault)

        return vault

    async def import_package(self, filename, target_folder, pull_vault=False):
        if os.path.exists(target_folder):
            raise ValueError('Folder "{0}" already exists.'.format(target_folder))

        with ZipFile(filename, 'r') as myzip:
            myzip.extractall(target_folder)

        logger.info('Imported vault into "%s"', target_folder)

        vault = Vault(target_folder)
        await self.open_or_init(vault)

        if pull_vault:
            await self.pull_vault(vault)
        return vault

    async def export_package(self, filename, vault=None):
        if vault is None:
            vault = self.vaults[0]
        export_pipe = vault.package_info()
        if filename is None:
            export_pipe = export_pipe >> StdoutWriter()
        else:
            export_pipe = export_pipe >> FileWriter(filename)
        await export_pipe.consume()
        if filename:
            logger.info("Vault export has been written to: %s" % filename)

    async def add_user_vault_key(self, vault, email, identity):
        # construct and encrypt package
        export_pipe = vault.package_info() \
            >> EncryptRSA_PKCS1_OAEP(identity.public_key)
        content = await export_pipe.readall()

        logger.info('Uploading vault package for %s/%s', email,
                format_fingerprint(identity.get_fingerprint()))
        logger.debug('Package length is: %d', len(content))

        await vault.backend.add_user_vault_key(email, identity.get_fingerprint(), content)

    async def upload_vault_key(self, vault=None):
        if vault is None:
            vault = self.vaults[0]
        await vault.backend.open()
        user_info = await vault.backend.user_info()
        email = user_info['email']
        await self.add_user_vault_key(vault, email, self.identity)

    async def get_remote_size_for_vault(self, vault):
        await vault.backend.open()
        return (await vault.backend.vault_size(vault))

    async def retrieve_metadata(self, vault):
        await vault.backend.open()
        return (await vault.backend.vault_metadata())

    #@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
    async def push(self):
        "Push all registered vaults"
        async with AsyncContext(concurrency=3) as ctx:
            for vault in self.vaults:

                #if vault.state != VaultState.READY:
                #    logger.warning("Skipping %s because it state is %s", vault, vault.state)
                #    continue

                await ctx.create_task(vault, self.push_vault(vault))
                for result in ctx.completed_tasks():
                    print("PUSHED_VAULT", result)
            await ctx.wait()
            for result in ctx.completed_tasks():
                print("PUSHED_VAULT", result)
                #try:
                    #logger.info('Pushing %s', vault)
                    #await vault.backend.open()
                    #await vault.backend.set_vault_metadata()

                    #for bundle in vault.walk_disk():
                    #    await ctx.create_task(bundle, self._push_bundle(bundle))
                #except VaultNotInitialized:
                #    logger.error('%s has not been initialized. Use "syncrypt init" to register the folder as vault.' % vault)
                #    continue
                #except VaultFolderDoesNotExist:
                #    logger.error('%s does not exist, removing vault from list.' % vault)
                #    await self.remove_vault(vault)
                #   continue

    async def push_vault(self, vault):
        "Push a single vault"
        logger.info('Pushing %s', vault)

        try:
            await self.set_vault_state(vault, VaultState.SYNCING)
            await vault.backend.open()
            await vault.backend.set_vault_metadata()

            async with AsyncContext(self._bundle_actions) as ctx:
                for bundle in vault.walk_disk():
                    await ctx.create_task(bundle, self.push_bundle(bundle))
                    ctx.raise_for_failures()
                await ctx.wait()
                ctx.raise_for_failures()
            await self.set_vault_state(vault, VaultState.READY)
        except:
            await self.set_vault_state(vault, VaultState.FAILURE)

    #@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
    async def push_bundle(self, bundle):
        'update bundle and maybe upload'

        await self.semaphores['update'].acquire(bundle)
        try:
            await bundle.update()
        finally:
            await self.semaphores['update'].release(bundle)

        await self.semaphores['stat'].acquire(bundle)
        try:
            await bundle.vault.backend.stat(bundle)
            self.stats['stats'] += 1
        finally:
            await self.semaphores['stat'].release(bundle)

        if bundle.remote_hash_differs:
            await self.semaphores['upload'].acquire(bundle)
            try:
                await bundle.vault.backend.upload(bundle)
                self.stats['uploads'] += 1
            finally:
                await self.semaphores['upload'].release(bundle)

    async def pull(self, full=False):
        "Pull all registered vaults"

        async with AsyncContext(concurrency=3) as ctx:
            for vault in self.vaults:

                #if vault.state == VaultState.SYNCING:
                #    logger.warning("Skipping %s because it state is %s", vault, vault.state)
                #    continue

                await ctx.create_task(vault, self.pull_vault(vault, full=full))
                for result in ctx.completed_tasks():
                    print("PUSHED_VAULT", result)
            await ctx.wait()
            for result in ctx.completed_tasks():
                print("PUSHED_VAULT", result)

        """
        for vault in self.vaults:
            try:
                await self.pull_vault(vault, full=full)
            except VaultNotInitialized:
                logger.error('%s has not been initialized. Use "syncrypt init" to register the folder as vault.' % vault)
                continue
            except VaultFolderDoesNotExist:
                logger.error('%s does not exist, removing vault from list.' % vault)
                await this.remove_vault(vault)
                continue
            except Exception as e:
                print("EXCEPTION")
                logger.exception(e)
                continue
        await self.wait()
        """

    async def pull_vault_periodically(self, vault):
        while True:
            await asyncio.sleep(int(vault.config.get('vault.pull_interval')))
            await self.pull_vault(vault)

    async def pull_vault(self, vault, full=False):
        vault.logger.info('Pulling %s', vault)
        latest_revision = None
        total = 0
        successful = []

        await self.retrieve_metadata(vault)

        # TODO: do a change detection (.vault/metadata store vs filesystem)
        await self.open_or_init(vault)
        if not vault.revision or full:
            queue = await vault.backend.list_files()
        else:
            queue = await vault.backend.changes(vault.revision, None)

        async with AsyncContext(self._bundle_actions) as ctx:
            while True:
                item = await queue.get()
                if item is None:
                    break
                total += 1
                store_hash, metadata, server_info = item
                try:
                    bundle = await vault.add_bundle_by_metadata(store_hash, metadata)
                    await ctx.create_task(bundle, self.pull_bundle(bundle))
                except Exception as e:
                    vault.logger.exception(e)
                for result in ctx.completed_tasks():
                    if not result.exception():
                        successful.append(result)
                latest_revision = server_info.get('id') or latest_revision
            await ctx.wait()
            for result in ctx.completed_tasks():
                if not result.exception():
                    successful.append(result)

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

    async def pull_bundle(self, bundle):
        'update, maybe download, and then decrypt'
        await self.semaphores['update'].acquire(bundle)
        try:
            await bundle.update()
        finally:
            await self.semaphores['update'].release(bundle)

        await self.semaphores['stat'].acquire(bundle)
        try:
            await bundle.vault.backend.stat(bundle)
            self.stats['stats'] += 1
        finally:
            await self.semaphores['stat'].release(bundle)

        if bundle.remote_crypt_hash is None:
            logger.warn('File not found: %s', bundle)
            return

        if bundle.remote_hash_differs:
            await self.semaphores['download'].acquire(bundle)
            try:
                await bundle.vault.backend.download(bundle)
                self.stats['downloads'] += 1
            finally:
                await self.semaphores['download'].release(bundle)

    async def wait(self):
        await self._bundle_actions.join()

    async def close(self):
        await self.wait()
        for vault in self.vaults:
            await vault.close()
