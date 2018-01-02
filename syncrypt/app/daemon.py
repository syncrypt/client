import asyncio
import logging
from getpass import getpass

import syncrypt
from syncrypt.api import APIClient, SyncryptAPI
from syncrypt.app.auth import AuthenticationProvider
from syncrypt.models import VaultState
from syncrypt.exceptions import VaultFolderDoesNotExist, VaultNotInitialized

from ..utils.updates import is_update_available
from .syncrypt import SyncryptApp

logger = logging.getLogger(__name__)


class SyncryptDaemonApp(SyncryptApp):

    def __init__(self, config, **kwargs):

        self.shutdown_event = asyncio.Event()
        self.restart_flag = False

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

        for vault in self.vaults:
            try:
                await self.check_vault(vault)
                await self.set_vault_state(vault, VaultState.READY)
            except VaultFolderDoesNotExist:
                logger.error('%s does not exist, removing vault from list.' % vault)
                await self.remove_vault(vault)
            except Exception as e:
                logger.exception(e)
                continue

        await self.push()

        #for vault in self.vaults:
        #    try:
        #        await self.watch_vault(vault)
        #    except VaultFolderDoesNotExist:
        #        logger.error('%s does not exist, removing vault from list.' % vault)
        #        await self.remove_vault(vault)
        #
        #try:
        #except Exception as e:
        #    logger.exception(e)
        #    logger.warn('The above exception occured while pushing vaults, we will try to continue anyway')
        #
        #for vault in self.vaults:
        #    await self.autopull_vault(vault)

    async def stop(self):
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
