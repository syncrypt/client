# pylint: disable=not-async-context-manager
import logging
import os.path
import socket
from typing import Any, Dict, List, Optional  # pylint: disable=unused-import
from zipfile import ZipFile

import smokesignal
import trio
from sqlalchemy import inspect
from sqlalchemy.orm.exc import NoResultFound
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential
from trio_typing import Nursery

from syncrypt.exceptions import (AlreadyPresent, FolderExistsAndIsNotEmpty, InvalidAuthentification,
                                 InvalidVaultPackage, SyncRequired, SyncryptBaseException,
                                 UnexpectedParentInRevision, VaultAlreadyExists,
                                 VaultIsAlreadySyncing, VaultNotFound, VaultNotInitialized)
from syncrypt.managers import (BundleManager, FlyingVaultManager, RevisionManager,
                               UserVaultKeyManager, VaultManager, VaultUserManager)
from syncrypt.models import Bundle, Identity, IdentityState, Vault, VaultState, store
from syncrypt.pipes import (DecryptRSA_PKCS1_OAEP, EncryptRSA_PKCS1_OAEP, FileWriter, Once,
                            StdoutWriter)
from syncrypt.utils.filesystem import is_empty
from syncrypt.utils.format import format_fingerprint

from .vault import VaultController

logger = logging.getLogger(__name__)


class SyncryptApp(object):
    '''
    The main controller class for Syncrypt commands. A single instance of this class can
    orchestrate multiple vaults.
    '''

    def __init__(self, config, auth_provider=None, vault_dirs=None, nursery=None):
        self.auth_provider = auth_provider
        self.vaults = [] # type: List[Vault]
        self.vault_dirs = vault_dirs
        self.config = config
        self.nursery = nursery # type: Nursery
        self.vault_controllers = {} # type: Dict[str, VaultController]
        self.concurrency = int(self.config.app['concurrency'])

        # These enforce global limits on various bundle actions
        self.limiters = {
            'update': trio.CapacityLimiter(8),
            'stat': trio.CapacityLimiter(8),
            'upload': trio.CapacityLimiter(8),
            'download': trio.CapacityLimiter(8),
        } # type: Dict[str, trio.CapacityLimiter]

        self.stats = {
            'uploads': 0,
            'downloads': 0,
        }

        # A map from Bundle -> Future that contains all bundles scheduled for a push
        self._scheduled_pushes = {} # type: Dict[Bundle, Any]

        # A map from Bundle -> Task that contains all running pushes
        self._running_pushes = {} # type: Dict[Bundle, Any]

        # A map from Bundle -> Exception that contains all failed pushes
        self._failed_pushes = {} # type: Dict[Bundle, Any]

        # A map from folder -> Watchdog. Used by the daemon and the "watch" command.
        self._watchdogs = {} # type: Dict[str, Any]

        # A map from folder -> Task. Used by the daemon to autopull vault periodically.
        self._autopull_tasks = {} # type: Dict[str, Any]

        store.init(config)

        self.flying_vaults = FlyingVaultManager(self)
        self.db_vaults = VaultManager(self) # might be renamed to/merged with self.vaults
        self.revisions = RevisionManager(self)
        self.bundles = BundleManager(self)
        self.user_vault_keys = UserVaultKeyManager(self)
        self.vault_users = VaultUserManager(self)

        self.identity = Identity(os.path.join(self.config.config_dir,
                                              self.config.get('identity.private_key')),
                                 os.path.join(self.config.config_dir,
                                              self.config.get('identity.public_key')),
                                 self.config)

        super(SyncryptApp, self).__init__()

    async def initialize(self):
        await self.identity.init()

        if self.vault_dirs is None:
            self.vault_dirs = self.config.vault_dirs

        # Load cached vault information from config file
        config_vaults = []
        with store.session() as session:
            for vault_dir in self.vault_dirs:
                abs_vault_dir = os.path.normpath(os.path.abspath(vault_dir))
                try:
                    vault = session.query(Vault).filter(Vault.folder==abs_vault_dir).one()
                except NoResultFound:
                    vault = Vault(abs_vault_dir)
                    session.add(vault)
                config_vaults.append(vault)

        for vault in config_vaults:
            await self.start_vault(vault)

    async def signup(self, username, password, firstname, surname):
        backend = self.config.backend_cls(**self.config.backend_kwargs)
        await backend.signup(username, password, firstname, surname)

    def vault_controller(self, vault):
        return VaultController(self, vault)

    async def start_vault(self, vault, async_init: bool = False, async_push: bool = False,
            async_pull: bool = False):
        logger.info("Registering vault %s", vault)
        assert vault.id not in self.vault_controllers
        self.vaults.append(vault)
        vault_controller = self.vault_controller(vault)
        self.vault_controllers[vault.id] = vault_controller
        await self.nursery.start(vault_controller.run, async_init, async_push, async_pull)

    async def stop_vault(self, vault):
        assert vault.id in self.vault_controllers
        self.vaults.remove(vault)
        await self.vault_controllers[vault.id].cancel()
        del self.vault_controllers[vault.id]

    async def remove_vault(self, vault):
        logger.info("Removing vault %s", vault)
        with self.config.update_context():
            self.config.remove_vault_dir(os.path.abspath(vault.folder))
        await self.reset_vault_database(vault, remove_vault=True)
        await self.stop_vault(vault)

    async def add_vault(self, vault, async_pull: bool = False, async_init: bool = False, async_push: bool = False):
        for v in self.vaults:
            if os.path.abspath(v.folder) == os.path.abspath(vault.folder):
                raise VaultIsAlreadySyncing(v.folder)
        logger.info("Adding vault %s", vault)
        await self.reset_vault_database(vault, remove_vault=True)
        with self.config.update_context():
            self.config.add_vault_dir(os.path.abspath(vault.folder))
        await self.start_vault(
            vault,
            async_pull=async_pull,
            async_init=async_init,
            async_push=async_push
        )
        return vault

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
            logger.debug('Cancel shedule for %s', bundle)
            self._scheduled_pushes[bundle].cancel()
            del self._scheduled_pushes[bundle]
        if bundle in self._running_pushes:
            logger.warning('Update/upload for %s is running, aborting it now.', bundle)
            self._running_pushes[bundle].cancel()
            del self._running_pushes[bundle]

    def schedule_push(self, bundle):
        self.cancel_push(bundle)
        logger.debug('Scheduling update for %s', bundle)
        controller = self.vault_controllers[bundle.vault.id]

        async def push_scheduled(bundle):
            with trio.CancelScope() as cancel_scope:
                if bundle in self._scheduled_pushes:
                    return
                self._scheduled_pushes[bundle] = cancel_scope
                await trio.sleep(1.0)
                del self._scheduled_pushes[bundle]
                logger.debug('Scheduled update is executing for %s', bundle)
                assert controller.nursery is not None
                controller.nursery.start_soon(self.maybe_push_bundle, bundle)

        assert controller.nursery is not None
        controller.nursery.start_soon(push_scheduled, bundle)

    async def init_vault(self, vault, remote=None, upload_vault_key=True, upload_identity=True):
        async with self.vault_controllers[vault.id].lock:
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
                logger.warning('Vault %s already initialized', vault.folder)
                return
            except (InvalidAuthentification, VaultNotInitialized):
                pass

            logger.info("Initializing %s", vault)
            await self.reset_vault_database(vault, remove_vault=True)

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
            await self.update_vault_metadata(vault)

            if upload_identity:
                await vault.backend.upload_identity(self.identity)
            if upload_vault_key:
                await self.upload_vault_key(vault)

    async def init(self, host: Optional[str] = None, upload_vault_key: bool = True):
        for vault in self.vaults:
            remote = None # type: Optional[Dict[str, Any]]
            if host:
                remote = dict(self.config.remote)
                remote['host'] = host
            await self.init_vault(vault, remote=remote)

    async def update_vault_metadata(self, vault):
        """
        Here we will check if we need to update the metadata on the server. If so, create a
        revision and apply it.
        """
        if not vault.require_metadata_update():
            logger.debug("Vault metadata unchanged, skipping update")
            return

        if vault.state == VaultState.UNINITIALIZED or vault.identity.public_key is None:
            logger.debug("Skipping vault metadata update, because vault key is not ready yet.")
            return

        logger.debug("Vault Metadata changed, we will write a new revision")
        logger.debug("Metadata is: %s", vault.remote_metadata)
        logger.debug("Metadata should be: %s", vault.serialized_metadata)
        revision = await vault.backend.set_vault_metadata(self.identity)
        await self.revisions.apply(revision, vault)

    async def upload_identity(self):
        backend = await self.open_backend()
        description = socket.gethostname()
        await backend.upload_identity(self.identity, description)
        logger.info('Uploaded public key with fingerprint "{0}".'.format(
            format_fingerprint(self.identity.get_fingerprint())))

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
            controller = self.vault_controllers.get(vault.id)

            if controller:
                await controller.handle_state_transition(new_state, old_state)
            else:
                logger.debug('Ignoring vault state change for unregistered vault: %s', vault)

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

        await self.add_vault(Vault(clone_target))

        await self.pull()

    async def _list_vaults_with_name(self):
        logger.debug('Retrieving vault list...')
        backend = await self.open_backend()
        vaults = []

        for (vault, user_vault_key, encrypted_metadata) in \
                    (await backend.list_vaults_for_identity(self.identity)):

            vault_id = vault['id'].decode('utf-8')

            logger.debug("Received vault: %s (with%s metadata)", vault_id, '' if encrypted_metadata else 'out')

            name = ""
            if encrypted_metadata:
                metadata = await self._decrypt_metadata(encrypted_metadata, user_vault_key)
                if 'name' in metadata:
                    name = metadata['name']

            vaults.append((vault_id, name))

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

        serialized_metadata = await sink.readall()
        return umsgpack.unpackb(serialized_metadata)

    async def set(self, setting, value):
        for vault in self.vaults:
            await self.sync_vault(vault) # we need to be synced in order to update the metadata
            with vault.config.update_context():
                vault.config.set(setting, value)
            await self.update_vault_metadata(vault)

    async def unset(self, setting):
        for vault in self.vaults:
            await self.sync_vault(vault) # we need to be synced in order to update the metadata
            with vault.config.update_context():
                vault.config.unset(setting)
            await self.update_vault_metadata(vault)

    async def check_vault(self, vault: Vault):
        await vault.backend.open()

    async def resync_vault(self, vault: Vault):
        controller = self.vault_controllers.get(vault.id)
        if controller is None:
            raise VaultNotFound(vault.id)
        await controller.resync()

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

    async def clone(self, vault_id, local_directory, async_init: bool = False):
        backend = await self.open_backend()

        logger.info('Retrieving encrypted key for vault %s (Fingerprint: %s)',
                vault_id, format_fingerprint(self.identity.get_fingerprint()))
        auth_token, package_info = await \
                backend.get_user_vault_key(self.identity.get_fingerprint(), vault_id)

        # decrypt package
        export_pipe = Once(package_info) \
            >> DecryptRSA_PKCS1_OAEP(self.identity.private_key)

        decrypted_package_info = await export_pipe.readall()

        original_vault = self.get_vault_by_path(local_directory)
        if original_vault:
            if original_vault.config.id == vault_id:
                logger.warning('Same vault already exists in the given location, continuing...')
                vault = original_vault
            else:
                raise VaultAlreadyExists(original_vault.folder)
        else:
            # There is no vault present, but we want to make sure that this folder is nonexistent or
            # empty:
            if os.path.exists(local_directory) and not is_empty(local_directory):
                raise FolderExistsAndIsNotEmpty(local_directory)

            vault = Vault.from_package_info(decrypted_package_info, local_directory, auth_token)

        if not async_init:
            await self.pull_vault(vault, full=True)

        await self.add_vault(vault, async_init=async_init)

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

    async def add_vault_user(self, vault, user_id):
        if self.vault_users.exists(vault, user_id):
            raise AlreadyPresent(user_id)
        revision = await vault.backend.add_vault_user(user_id, self.identity)
        await self.revisions.apply(revision, vault)

    async def remove_vault_user(self, vault, user_id):
        revision = await vault.backend.remove_vault_user(user_id, self.identity)
        await self.revisions.apply(revision, vault)

    async def add_user_vault_key(self, vault, email, identity):
        # construct and encrypt package
        export_pipe = vault.package_info() \
            >> EncryptRSA_PKCS1_OAEP(identity.public_key)
        content = await export_pipe.readall()

        logger.info('Uploading vault package for %s/%s', email,
                format_fingerprint(identity.get_fingerprint()))
        logger.debug('Package length is: %d', len(content))

        revision = await vault.backend.add_user_vault_key(
            self.identity, email, identity, content
        )
        await self.revisions.apply(revision, vault)

    async def remove_user_vault_key(self, vault, email, identity):
        revision = await vault.backend.remove_user_vault_key(self.identity, email, identity)
        await self.revisions.apply(revision, vault)

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
        logger.debug('Refreshing vault information (byte_size) from server...')
        backend = await self.open_backend()

        with store.session() as session:
            for v_info in (await backend.list_vaults()):

                remote_id = v_info['id'].decode()

                for v in self.vaults:
                    try:
                        if v.config.id == remote_id:
                            byte_size = int(v_info.get('byte_size', 0))
                            if byte_size != v.byte_size:
                                logger.debug('Updating byte size for vault %s to %d', remote_id, byte_size)
                                v.byte_size = byte_size
                                session.add(v)
                    except SyncryptBaseException:
                        pass

    async def push(self):
        "Push all registered vaults"
        async with trio.open_nursery() as nursery:
            for vault in self.vaults:
                if not self.identity.is_initialized():
                    logger.error('Identity is not initialized yet')
                    await self.set_vault_state(vault, VaultState.UNINITIALIZED)
                    continue

                nursery.start_soon(self.push_vault, vault)

    async def push_vault(self, vault):
        "Push a single vault"

        logger.info('Pushing %s', vault)

        try:
            self.identity.assert_initialized()

            await self.sync_vault(vault)
            limit = trio.CapacityLimiter(1)

            await self.set_vault_state(vault, VaultState.SYNCING)
            async with trio.open_nursery() as nursery:
                await vault.backend.open()
                await self.update_vault_metadata(vault)

                async for bundle in self.bundles.upload_bundles_for_vault(vault):
                    async with limit:
                        await self.push_bundle(bundle)
                        # nursery.start_soon(self.push_bundle, bundle)

                await self.set_vault_state(vault, VaultState.READY)
        except Exception:
            vault.logger.exception("Failure during vault push")
            await self.set_vault_state(vault, VaultState.FAILURE)

    async def maybe_push_bundle(self, bundle: Bundle):
        await bundle.update()

        if bundle.remote_hash_differs:
            await self.push_bundle(bundle)

    async def push_bundle(self, bundle: Bundle):
        'upload the bundle'

        if inspect(bundle.vault).session:
            raise ValueError('Vault object is bound to a session')

        async with self.limiters['upload']:
            while True:
                try:
                    revision = await bundle.vault.backend.upload(bundle, self.identity)
                    await self.revisions.apply(revision, bundle.vault)
                    break
                except SyncRequired:
                    await trio.sleep(1)
                    await self.sync_vault(bundle.vault) # deadlock?

            self.stats['uploads'] += 1

    async def pull(self, full=False):
        "Pull all registered vaults"

        self.identity.assert_initialized()

        async with trio.open_nursery() as nursery:
            for vault in self.vaults:

                if vault.state == VaultState.SYNCING:
                    logger.warning("Skipping %s because it state is %s", vault, vault.state)
                    continue

                if not self.identity.is_initialized():
                    logger.error('Identity is not initialized yet')
                    await self.set_vault_state(vault, VaultState.FAILURE)
                    continue

                nursery.start_soon(self.pull_vault, vault, full)

    async def reset_vault_database(self, vault, remove_vault=False):
        await self.revisions.delete_for_vault(vault)
        await self.user_vault_keys.delete_for_vault(vault)
        await self.vault_users.delete_for_vault(vault)
        await self.bundles.delete_for_vault(vault)
        if remove_vault:
            await self.db_vaults.delete(vault.id)
        else:
            await self.db_vaults.reset(vault)
            vault.reset_revision()
            assert vault.revision_count == 0
            assert vault.revision is None

    #@retry(retry=retry_if_exception_type(UnexpectedParentInRevision),
    #       stop=stop_after_attempt(5),
    #       wait=wait_exponential(multiplier=1, max=10))
    async def sync_vault(self, vault, full=False):

        async with self.vault_controllers[vault.id].lock:
            if full:
                await self.reset_vault_database(vault)

            #await self.open_or_init(vault)
            async for revision in vault.backend.changes(vault.revision, None):
                await self.set_vault_state(vault, VaultState.SYNCING)
                await self.revisions.apply(revision, vault)

            await self.set_vault_state(vault, VaultState.READY)

    async def pull_vault(self, vault, full=False):
        with trio.fail_after(5*60):
            while vault.state == VaultState.SYNCING:
                await trio.sleep(0.5)

        vault.logger.info('Pulling %s', vault)

        # First, we will iterate through the changes, validate the chain and build up the state of
        # the vault (files, keys, ...). This is called "syncing".
        await self.sync_vault(vault, full=full)

        async with self.vault_controllers[vault.id].lock:
            await self.set_vault_state(vault, VaultState.SYNCING)
            # Then, we will do a change detection for the local folder and download every bundle that
            # has changed.
            # TODO: do a change detection (.vault/metadata store vs filesystem)
            limit = trio.CapacityLimiter(1)

            try:
                # here we should use trimeter too allow for parallel processing
                async with trio.open_nursery():
                    async for bundle in self.bundles.download_bundles_for_vault(vault):
                        async with limit:
                            await self.pull_bundle(bundle)

                    await self.set_vault_state(vault, VaultState.READY)
            except Exception:
                vault.logger.exception("Failure while pulling vault")
                await self.set_vault_state(vault, VaultState.FAILURE)
            await self.set_vault_state(vault, VaultState.READY)

    async def pull_bundle(self, bundle):
        'download the bundle'
        async with self.limiters['download']:
            await bundle.vault.backend.download(bundle)
            self.stats['downloads'] += 1

    async def remove_bundle(self, bundle: Bundle):
        vault = bundle.vault
        revision = await vault.backend.remove_file(bundle, self.identity)
        await self.revisions.apply(revision, vault)

    async def remove_file(self, vault: Vault, path: str):
        abs_path = os.path.normpath(os.path.abspath(path))
        bundle = await self.bundles.get_bundle(vault, abs_path)
        await self.remove_bundle(bundle)

    #async def remove_file(self, path: str):
    #    full_path = os.path.normpath(os.path.abspath(path))
    #    bundle = None # type: Optional[Bundle]
    #    for vault in self.vaults:
    #        vault_folder = os.path.abspath(vault.folder)
    #        if os.path.commonpath([vault_folder]) == os.path.commonpath(
    #                [vault_folder, full_path]
    #                ):
    #            bundle = Bundle(
    #                    vault=vault, relpath=os.path.relpath(full_path, vault.folder)
    #                    )
    #            bundle.update_store_hash()
    #            break
    #    if bundle is None:
    #        raise ValueError("could not find path '{0}' in any vault".format(full_path))
    #    else:
    #        await self.remove_bundle(bundle)

    async def wait(self):
        pass # TODO

    async def close(self):
        await self.wait()
        for vault in list(self.vaults):
            await self.set_vault_state(vault, VaultState.SHUTDOWN)
            await self.stop_vault(vault)
        smokesignal.emit('shutdown')
