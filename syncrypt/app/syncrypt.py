import asyncio
import logging
import os.path
import socket
import sys
from typing import Optional, List, Dict, Any
from zipfile import ZipFile

from sqlalchemy.orm.exc import NoResultFound

import syncrypt
from syncrypt.exceptions import (FolderExistsAndIsNotEmpty, InvalidAuthentification,
                                 InvalidVaultPackage, SyncryptBaseException, VaultAlreadyExists,
                                 VaultFolderDoesNotExist, VaultIsAlreadySyncing, VaultNotFound,
                                 VaultNotInitialized)
from syncrypt.managers import (BundleManager, FlyingVaultManager, RevisionManager,
                               UserVaultKeyManager)
from syncrypt.models import Bundle, Identity, IdentityState, Vault, VaultState, store
from syncrypt.pipes import (DecryptRSA_PKCS1_OAEP, EncryptRSA_PKCS1_OAEP, FileWriter, Once,
                            SnappyCompress, StdoutWriter)
from syncrypt.utils.filesystem import is_empty
from syncrypt.utils.format import format_fingerprint, format_size, size_with_unit
from syncrypt.utils.semaphores import JoinableSemaphore, JoinableSetSemaphore

from .asynccontext import AsyncContext

logger = logging.getLogger(__name__)


class SyncryptApp(object):
    '''
    The main controller class for Syncrypt commands. A single instance of this class can
    orchestrate multiple vaults.
    '''

    def __init__(self, config, auth_provider=None, vault_dirs=None):
        self.auth_provider = auth_provider
        self.vaults = [] # type: List[Vault]
        self.config = config
        self.concurrency = int(self.config.app['concurrency'])

        # These enforce global limits on various bundle actions
        self.semaphores = {
            'update': JoinableSetSemaphore(8),
            'stat': JoinableSetSemaphore(8),
            'upload': JoinableSetSemaphore(8),
            'download': JoinableSetSemaphore(8)
        } # type: Dict[str, JoinableSetSemaphore[Bundle]]

        self.stats = {
            'uploads': 0,
            'downloads': 0,
            'stats': 0
        }

        # A map from Bundle -> Future that contains all bundles scheduled for a push
        self._scheduled_pushes = {} # type: Dict[Bundle, Any]

        # A map from Bundle -> Task that contains all running pushes
        self._running_pushes = {} # type: Dict[Bundle, Any]

        # A map from Bundle -> Exception that contains all failed pushes
        self._failed_pushes = {} # type: Dict[Bundle, Any]

        # This semaphore enforces the global concurrency limit for both pushes and pulls.
        self._bundle_actions = JoinableSemaphore(self.concurrency)

        # A map from folder -> Watchdog. Used by the daemon and the "watch" command.
        self._watchdogs = {} # type: Dict[str, Any]

        # A map from folder -> Task. Used by the daemon to autopull vault periodically.
        self._autopull_tasks = {} # type: Dict[str, Any]

        def handler(loop, args, **kwargs):
            if 'exception' in kwargs and isinstance(kwargs['exception'], asyncio.CancelledError):
                return
            logger.error("Unhandled exception in event loop: %s, %s", args, kwargs)
        asyncio.get_event_loop().set_exception_handler(handler)

        store.init(config)

        self.flying_vaults = FlyingVaultManager(self)
        self.revisions = RevisionManager(self)
        self.bundles = BundleManager(self)
        self.user_vault_keys = UserVaultKeyManager(self)

        self.identity = Identity(os.path.join(self.config.config_dir,
                                              self.config.get('identity.private_key')),
                                 os.path.join(self.config.config_dir,
                                              self.config.get('identity.public_key')),
                                 self.config)

        if vault_dirs is None:
            vault_dirs = self.config.vault_dirs

        # Load cached vault information from config file
        with store.session() as session:
            for vault_dir in vault_dirs:
                try:
                    vault = session.query(Vault).filter(Vault.folder==vault_dir).one()
                except NoResultFound:
                    vault = Vault(vault_dir)
                    session.add(vault)
                self.vaults.append(vault)

        super(SyncryptApp, self).__init__()

    async def initialize(self):
        await self.identity.init()

        for vault in self.vaults:
            try:
                vault.check_existence()
                self.identity.assert_initialized()
            except SyncryptBaseException as e:
                logger.exception("Failure during vault initialization")
                await self.set_vault_state(vault, VaultState.FAILURE)

    async def signup(self, username, password, firstname, surname):
        backend = self.config.backend_cls(**self.config.backend_kwargs)
        await backend.signup(username, password, firstname, surname)

    def add_vault_by_path(self, path):
        v = Vault(path)
        return self.add_vault(v)

    def add_vault(self, vault):
        for v in self.vaults:
            if os.path.abspath(v.folder) == os.path.abspath(vault.folder):
                raise VaultIsAlreadySyncing(v.folder)
        self.vaults.append(vault)
        return vault

    def save_vault_dir_in_config(self, vault):
        with self.config.update_context():
            self.config.add_vault_dir(os.path.abspath(vault.folder))

    def find_vault_by_id(self, vault_id):
        for v in self.vaults:
            if v.id == vault_id:
                return v
        raise VaultNotFound('Vault not found: {}'.format(vault_id))

    def get_vault_by_path(self, path):
        vault = Vault(path)
        if os.path.exists(vault.config_path):
            return vault
        return None

    async def remove_vault(self, vault):
        with self.config.update_context():
            self.config.remove_vault_dir(os.path.abspath(vault.folder))
        self.vaults.remove(vault)

    async def delete_vault(self, vault):
        await vault.backend.open()
        await vault.backend.delete_vault()
        await self.remove_vault(vault)
        await vault.delete()

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

    async def init_vault(self, vault, remote=None, upload_vault_key=True, upload_identity=True):
        self.identity.assert_initialized()

        if remote:
            # If remote was explicitly given, use it
            vault.config.update('remote', remote)
            vault.backend.host = self.config.get('remote.host')
        else:
            # otherwise, use remote from global config
            vault.config.update('remote', self.config.remote)
            vault.backend.host = self.config.get('remote.host')

        try:
            await vault.backend.open()
            logger.warn('Vault %s already initialized', vault.folder)
            return
        except (InvalidAuthentification, VaultNotInitialized):
            pass
        logger.info("Initializing %s", vault)
        await vault.identity.init()
        if vault.identity.state != IdentityState.INITIALIZED:
            await vault.identity.generate_keys()
        global_auth = self.config.remote.get('auth')
        if global_auth:
            logger.debug('Using user auth token to initialize vault.')
            vault.backend.global_auth = global_auth
        try:
            revision = await vault.backend.init(self.identity)
        except InvalidAuthentification:
            vault.backend.global_auth = None
            username, password = await self.auth_provider.get_auth(vault.backend)
            vault.backend.set_auth(username, password)
            revision = await vault.backend.init(self.identity)

        logger.debug('Vault has been created by %s', revision)

        await self.revisions.apply(revision, vault)

        await self.set_vault_state(vault, VaultState.READY)
        with vault.config.update_context():
            vault.config.set('vault.name', os.path.basename(os.path.abspath(vault.folder)))
        revision = await vault.backend.set_vault_metadata(self.identity)
        await self.revisions.apply(revision, vault)

        if upload_identity:
            await vault.backend.upload_identity(self.identity)
        if upload_vault_key:
            await self.upload_vault_key(vault)

    async def init(self, host: Optional[str] = None, upload_vault_key: bool = False):
        for vault in self.vaults:
            remote = None # type: Optional[Dict[str, Any]]
            if host:
                remote = dict(self.config.remote)
                remote['host'] = host
            await self.init_vault(vault, remote=remote)

    async def upload_identity(self):
        backend = await self.open_backend()
        description = socket.gethostname()
        await backend.upload_identity(self.identity, description)
        logger.info('Uploaded public key with fingerprint "{0}".'.format(
            format_fingerprint(self.identity.get_fingerprint())))
        await backend.close()

    async def open_or_init(self, vault):
        try:
            if not os.path.exists(vault.config_path):
                vault.config.update('remote', self.config.remote)
            await vault.backend.open()
        except (InvalidAuthentification, VaultNotInitialized):
            # retry after logging in & getting auth token
            # use the host from the app config
            await self.init_vault(vault)
            await vault.backend.open()

    async def set_vault_state(self, vault, new_state):
        if vault.state != new_state:
            old_state = vault.state
            vault.state = new_state
            await self.handle_state_transition(vault, old_state)

    async def handle_state_transition(self, vault, old_state):
        pass

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
                    raise InvalidAuthentification('Can not login, do not have auth provider')
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
            except InvalidAuthentification as e:
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

        original_vault = self.get_vault_by_path(local_directory)
        if original_vault:
            if original_vault.config.id == vault_id:
                logger.warn('Same vault already exists in the given location, continuing...')
                vault = original_vault
            else:
                raise VaultAlreadyExists(original_vault.folder)
        else:
            # There is no vault present, but we want to make sure that this folder is nonexistent or
            # empty:
            if os.path.exists(local_directory) and not is_empty(local_directory):
                raise FolderExistsAndIsNotEmpty(local_directory)

            vault = Vault.from_package_info(decrypted_package_info, local_directory, auth_token)

        self.add_vault(vault)

        await self.pull_vault(vault, full=True)

        return vault

    async def import_package(self, filename, target_folder, pull_vault=False):

        if os.path.exists(target_folder) and not is_empty(target_folder):
            raise FolderExistsAndIsNotEmpty(target_folder)

        with ZipFile(filename, 'r') as myzip:
            myzip.extractall(target_folder)

        logger.info('Importing vault into "%s"', target_folder)

        vault = Vault(target_folder)
        if not vault.config.id:
            raise InvalidVaultPackage()

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

    async def export_user_key(self, filename):
        export_pipe = self.identity.package_info()
        if filename is None:
            export_pipe = export_pipe >> StdoutWriter()
        else:
            export_pipe = export_pipe >> FileWriter(filename)
        await export_pipe.consume()
        if filename:
            logger.info("Key has been written to: %s", filename)

    async def import_user_key(self, filename):
        self.identity.import_from_package(filename)
        logger.info("Imported user key with fingerprint: %s", self.identity.get_fingerprint())

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
        self.identity.assert_initialized()
        if vault is None:
            vault = self.vaults[0]
        await vault.backend.open()
        user_info = await vault.backend.user_info()
        email = user_info['email']
        await self.add_user_vault_key(vault, email, self.identity)

    async def get_remote_size_for_vault(self, vault):
        await vault.backend.open()
        return (await vault.backend.vault_size(vault))

    async def refresh_vault_info(self):
        logger.info('Refreshing vault information')
        backend = await self.open_backend()

        with store.session() as session:
            for v_info in (await backend.list_vaults()):

                remote_id = v_info['id'].decode()

                for v in self.vaults:
                    if v.config.id == remote_id:
                        v.byte_size = int(v_info.get('byte_size', 0))
                        v.file_count = int(v_info.get('file_count', 0))
                        v.user_count = int(v_info.get('user_count', 0))
                        v.revision_count = int(v_info.get('revision_count', 0))
                        modification_date = v_info.get('modification_date') or b''
                        v.modification_date = modification_date.decode()
                        session.add(v)

        for vault in self.vaults:
            await self.revisions.update_for_vault(vault)

        await backend.close()

    async def push(self):
        "Push all registered vaults"
        async with AsyncContext(concurrency=3) as ctx:
            for vault in self.vaults:

                if not self.identity.is_initialized():
                    logger.error('Identity is not initialized yet')
                    await self.set_vault_state(vault, VaultState.FAILURE)
                    continue

                await ctx.create_task(vault, self.push_vault(vault))
                for result in ctx.completed_tasks():
                    pass
            await ctx.wait()
            for result in ctx.completed_tasks():
                pass

    async def push_vault(self, vault):
        "Push a single vault"
        logger.info('Pushing %s', vault)

        self.identity.assert_initialized()

        try:
            await self.set_vault_state(vault, VaultState.SYNCING)
            await vault.backend.open()
            revision = await vault.backend.set_vault_metadata(self.identity)
            await self.revisions.apply(revision, vault)

            async with AsyncContext(self._bundle_actions) as ctx:
                for bundle in vault.walk_disk():
                    await ctx.create_task(bundle, self.push_bundle(bundle))
                    ctx.raise_for_failures()
                await ctx.wait()
                ctx.raise_for_failures()
            await self.set_vault_state(vault, VaultState.READY)
        except Exception as e:
            vault.logger.exception(e)
            await self.set_vault_state(vault, VaultState.FAILURE)

    async def push_bundle(self, bundle: Bundle):
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
                revision = await bundle.vault.backend.upload(bundle, self.identity)
                await self.revisions.apply(revision, bundle.vault)
                self.stats['uploads'] += 1
            finally:
                await self.semaphores['upload'].release(bundle)

    async def pull(self, full=False):
        "Pull all registered vaults"

        self.identity.assert_initialized()

        async with AsyncContext(concurrency=3) as ctx:
            for vault in self.vaults:

                #if vault.state == VaultState.SYNCING:
                #    logger.warning("Skipping %s because it state is %s", vault, vault.state)
                #    continue

                if not self.identity.is_initialized():
                    logger.error('Identity is not initialized yet')
                    await self.set_vault_state(vault, VaultState.FAILURE)
                    continue

                await ctx.create_task(vault, self.pull_vault(vault, full=full))
                for result in ctx.completed_tasks():
                    pass
            await ctx.wait()
            for result in ctx.completed_tasks():
                pass

    async def pull_vault_periodically(self, vault):
        while True:
            await asyncio.sleep(int(vault.config.get('vault.pull_interval')))
            await self.pull_vault(vault)

    async def sync_vault(self, vault, full=False):

        if full:
            await self.revisions.delete_for_vault(vault)
            await self.user_vault_keys.delete_for_vault(vault)
            await self.bundles.delete_for_vault(vault)
            vault.reset_revision()

        await self.open_or_init(vault)
        queue = await vault.backend.changes(vault.revision if not full else None, None)

        while True:
            revision = await queue.get()
            if revision is None:
                break

            await self.revisions.apply(revision, vault)

    async def pull_vault(self, vault, full=False):
        vault.logger.info('Pulling %s', vault)
        latest_revision = None
        total = 0
        successful = []

        await self.set_vault_state(vault, VaultState.SYNCING)

        # First, we will iterate through the changes, validate the chain and build up the state of
        # the vault (files, keys, ...). This is called "syncing".
        await self.sync_vault(vault, full=full)

        # Then, we will do a change detection for the local folder and download every bundle that
        # has changed.
        # TODO: do a change detection (.vault/metadata store vs filesystem)
        async with AsyncContext(self._bundle_actions) as ctx:

            for bundle in (await self.bundles.download_bundles_for_vault(vault)):
                await ctx.create_task(bundle, self.pull_bundle(bundle))
                ctx.raise_for_failures()

            await ctx.wait()
            for result in ctx.completed_tasks():
                if not result.exception():
                    successful.append(result)

            await self.set_vault_state(vault, VaultState.READY)

        #success = len(successful) == total

        #if success:
        #    if total == 0:
        #        vault.logger.info('No changes in %s', vault)
        #    else:
        #        vault.logger.info('Successfully pulled %d revisions for %s', total, vault)
        #        if latest_revision:
        #            vault.update_revision(latest_revision)

        #    await self.set_vault_state(vault, VaultState.READY)
        #else:
        #    vault.logger.error('%s failure(s) occured while pulling %d revisions for %s',
        #            total - len(successful), total, vault)
        #    await self.set_vault_state(vault, VaultState.FAILURE)

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

    async def delete_bundle(self, bundle: Bundle):
        vault = bundle.vault
        revision = await vault.backend.delete_file(bundle, self.identity)
        await self.revisions.apply(revision, vault)

    async def delete_file(self, path: str):
        full_path = os.path.normpath(os.path.abspath(path))
        bundle = None # type: Optional[Bundle]
        for vault in self.vaults:
            vault_folder = os.path.abspath(vault.folder)
            if os.path.commonpath([vault_folder]) == os.path.commonpath(
                    [vault_folder, full_path]
                    ):
                bundle = Bundle(
                        vault=vault, relpath=os.path.relpath(full_path, vault.folder)
                        )
                bundle.update_store_hash()
                break
        if bundle is None:
            raise ValueError("could not find path '{0}' in any vault".format(full_path))
        else:
            await self.delete_bundle(bundle)

    async def wait(self):
        await self._bundle_actions.join()

    async def close(self):
        await self.wait()
        for vault in self.vaults:
            await vault.close()
