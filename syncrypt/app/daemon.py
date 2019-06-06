import asyncio
import logging
import os.path
from distutils.version import LooseVersion  # pylint: disable=import-error,no-name-in-module

import trio

import syncrypt
from syncrypt.api import SyncryptAPI
from syncrypt.api.client import APIClient
from syncrypt.exceptions import InvalidAuthentification, VaultFolderDoesNotExist
from syncrypt.models import VaultState

from .syncrypt import SyncryptApp
from .vault import VaultController

logger = logging.getLogger(__name__)


class SyncryptDaemonApp(SyncryptApp):

    def __init__(self, config, **kwargs):

        self.shutdown_event = trio.Event()
        self.restart_flag = False
        self.refresh_vault_info_task = None
        self.initial_push = kwargs.pop('initial_push', True)

        super(SyncryptDaemonApp, self).__init__(config, **kwargs)

        self.api = SyncryptAPI(self)

    def vault_controller(self, vault):
        return VaultController(self, vault, update_on_idle=True)

    async def start(self):
        try:
            # TODO: Look into nursery.start, maybe ready.wait() is not needed
            self.nursery.start_soon(self.api.start)
            await self.api.ready.wait()
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
        pass

    async def stop(self):
        if self.refresh_vault_info_task:
            self.refresh_vault_info_task.cancel()
        for vault in self.vaults:
            await self.unautopull_vault(vault)
        await self.api.stop()

    async def shutdown(self):
        await self.stop()
        self.shutdown_event.set()

    async def restart(self):
        logger.warning('Restart requested, shutting down...')
        self.restart_flag = True
        await self.shutdown()

    async def wait_for_shutdown(self):
        if not self.shutdown_event.is_set():
            await self.shutdown_event.wait()

    async def refresh_vault_info_periodically(self):
        while True:
            try:
                if self.vaults:
                    await self.refresh_vault_info()
            except:
                logger.exception('Exception while refreshing vaults')
            await asyncio.sleep(30.0)

