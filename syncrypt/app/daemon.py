import asyncio
import logging
import os.path
from distutils.version import LooseVersion  # pylint: disable=import-error,no-name-in-module

import syncrypt
from syncrypt.api import SyncryptAPI
from syncrypt.api.client import APIClient
from syncrypt.exceptions import InvalidAuthentification, VaultFolderDoesNotExist
from syncrypt.models import VaultState

from .events import create_watchdog
from .syncrypt import SyncryptApp

logger = logging.getLogger(__name__)


class SyncryptDaemonApp(SyncryptApp):

    def __init__(self, config, **kwargs):

        self.shutdown_event = asyncio.Event()
        self.restart_flag = False
        self.refresh_vault_info_task = None
        self.initial_push = kwargs.pop('initial_push', True)

        super(SyncryptDaemonApp, self).__init__(config, **kwargs)

        self.api = SyncryptAPI(self)

    async def start(self):
        try:
            self.api.initialize()
            await self.api.start()
        except OSError:
            logger.error('Port is blocked, could not start API REST server')
            logger.info('Attempting to query running server for version...')
            client = APIClient(self.config)
            r = await client.get('/v1/version/', params={'check_for_update': 0})
            c = await r.json()
            await r.release()
            other_version = LooseVersion(c['installed_version'])
            our_version =  LooseVersion(syncrypt.__version__)
            if other_version < our_version:
                logger.info('Starting takeover because other version (%s) is lower than ours (%s)!',
                        other_version, our_version)
                r = await client.get('/v1/shutdown/')
                await r.release()
                await asyncio.sleep(5.0)
                try:
                    await self.api.start()
                except OSError:
                    logger.error('After 5s, port is still blocked, giving up...')
                    self.shutdown_event.set()
                    return
            else:
                logger.info('Other version (%s) is higher or same as ours (%s), let\'s leave it alone...',
                        other_version, our_version)

                self.shutdown_event.set()
                return

    async def post_setup(self):

        for vault in list(self.vaults):
            try:
                await self.check_vault(vault)
                await self.set_vault_state(vault, VaultState.READY)
            except VaultFolderDoesNotExist:
                logger.error('%s does not exist, removing vault from list.' % vault)
                await self.remove_vault(vault)
            except InvalidAuthentification:
                logger.exception("Failure during vault initialization")
                await self.set_vault_state(vault, VaultState.FAILURE)
            except Exception:
                logger.exception("General failure during vault initialization")

        self.refresh_vault_info_task = asyncio.Task(self.refresh_vault_info_periodically())

        if self.initial_push:
            await self.push()

    async def stop(self):
        if self.refresh_vault_info_task:
            self.refresh_vault_info_task.cancel()
        for vault in self.vaults:
            await self.unwatch_vault(vault)
            await self.unautopull_vault(vault)
        await self.api.stop()

    async def shutdown(self):
        await self.stop()
        self.shutdown_event.set()

    async def restart(self):
        logger.warn('Restart requested, shutting down...')
        self.restart_flag = True
        await self.shutdown()

    async def wait_for_shutdown(self):
        if not self.shutdown_event.is_set():
            await self.shutdown_event.wait()

    async def handle_state_transition(self, vault, old_state):
        logger.debug('State transition of %s: %s -> %s', vault, old_state,
                     vault.state)
        new_state = vault.state

        if new_state in (VaultState.READY,):
            await self.watch_vault(vault)
            await self.autopull_vault(vault)
        else:
            if old_state in (VaultState.READY,):
                await self.unwatch_vault(vault)
                await self.unautopull_vault(vault)

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

    async def refresh_vault_info_periodically(self):
        while True:
            try:
                if self.vaults:
                    await self.refresh_vault_info()
            except:
                logger.exception('Exception while refreshing vaults')
            await asyncio.sleep(30.0)

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
