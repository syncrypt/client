import logging
import os.path
from functools import partial
from typing import Tuple

import trio
from trio_typing import Nursery

from syncrypt.exceptions import IdentityNotInitialized, SyncryptBaseException
from syncrypt.models import Vault, VaultState

from .events import MemoryChannelEventHandler, Watchdog


class VaultLoggerAdapter(logging.LoggerAdapter):
    def __init__(self, vault: Vault, logger) -> None:
        self.vault = vault
        super(VaultLoggerAdapter, self).__init__(logger, {})

    def process(self, msg, kwargs):
        return (msg, dict(kwargs, extra={'vault_id': self.vault.id}))


class VaultController:
    """
    The VaultController is part of the Syncrypt App and is instantiated for
    each Vault. It handles higher level vault functionality like sheduling
    pushes etc. It also reacts to state transitions.
    """
    def __init__(self, app, vault, update_on_idle=False):
        self.app = app
        self.vault = vault
        self.ready = trio.Event()
        self.nursery = None # type: Nursery
        self.update_on_idle = update_on_idle
        self.logger = VaultLoggerAdapter(self.vault, logging.getLogger(__name__))
        send_channel, receive_channel = trio.open_memory_channel(128) # type: Tuple[trio.abc.SendChannel, trio.abc.ReceiveChannel]
        self.file_changes_send_channel = send_channel # type: trio.abc.SendChannel
        self.file_changes_receive_channel = receive_channel # type: trio.abc.ReceiveChannel
        self.cancel_scope = trio.CancelScope()

    async def resync(self):
        assert self.nursery is not None
        self.nursery.start_soon(partial(self.app.sync_vault, self.vault, full=True))

    async def handle_state_transition(self, new_state, old_state):
        self.logger.debug('State transition: %s -> %s', old_state, new_state)

        if new_state == VaultState.READY:
            self.ready.set()
        else:
            self.ready.clear()

        if new_state == VaultState.SHUTDOWN:
            await self.vault.close()

    async def autopull_vault_task(self):
        'Install a regular autopull for the given vault'

        await self.ready.wait()

        folder = os.path.abspath(self.vault.folder)
        interval = int(self.vault.config.get('vault.pull_interval')) / 30
        self.logger.info('Auto-pulling %s every %d seconds', folder, interval)

        while True:
            await trio.sleep(interval)
            if self.vault.state == VaultState.READY:
                self.nursery.start_soon(self.app.pull_vault, self.vault)

    async def watchdog_task(self):
        self.logger.debug("watchdog_task started")

        await self.ready.wait()

        async with trio.open_nursery() as nursery:
            watchdog = Watchdog(self.vault.folder,
                event_handler=MemoryChannelEventHandler(self.file_changes_send_channel)
            )
            watchdog.start()
            try:
                await trio.sleep_forever()
            finally:
                self.logger.debug('watchdog_task stop_attempt')
                with trio.move_on_after(10) as cleanup_scope:
                    cleanup_scope.shield = True
                    await watchdog.stop()
                self.logger.debug("watchdog_task stopped")

    async def respond_to_file_changes(self):
        self.logger.debug("respond_to_file_changes started")
        async for filechange in self.file_changes_receive_channel:
            # print(filechange)
            if filechange.event_type == 'modified' or filechange.event_type == 'created':
                bundle = self.app.bundles.get_bundle_for_relpath(
                        os.path.relpath(filechange.src_path, self.vault.folder),
                        self.vault)
                if bundle is None:
                    self.logger.debug('Ignoring file change in %s', filechange.src_path)
                    continue

                self.app.schedule_push(bundle)

        await trio.sleep_forever()

    async def cancel(self):
        if self.nursery:
            self.nursery.cancel_scope.cancel()
        self.cancel_scope.cancel()

    async def run(self, do_init, do_push, task_status=trio.TASK_STATUS_IGNORED):
        assert self.nursery is None
        with self.cancel_scope:

            try:
                self.vault.check_existence()
                self.vault.identity.read()
                self.vault.identity.assert_initialized()
            except IdentityNotInitialized:
                self.logger.info("Identity not yet initialized.")
                await self.app.set_vault_state(self.vault, VaultState.UNINITIALIZED)
            except SyncryptBaseException:
                self.logger.exception("Failure during vault initialization")
                await self.app.set_vault_state(self.vault, VaultState.FAILURE)

            self.logger.debug("Finished vault initialization successfully.")

            self.task_status = task_status
            self.do_init = do_init
            self.do_push = do_push

            if self.task_status:
                self.task_status.started()
                self.task_status = None

            await self.loop()

    async def loop(self):
        assert self.nursery is None
        while True:
            try:
                async with trio.open_nursery() as nursery:
                    self.logger.debug("Opened nursery")
                    self.nursery = nursery

                    full_pull = self.do_init
                    if self.do_init:
                        await self.app.init_vault(self.vault)
                        self.do_init = None

                    if self.do_push:
                        await self.app.pull_vault(self.vault, full=full_pull)
                        await self.app.push_vault(self.vault)
                        self.do_push = None
                    else:
                        await self.app.pull_vault(self.vault)

                    if self.update_on_idle:
                        self.nursery.start_soon(self.respond_to_file_changes)
                        self.nursery.start_soon(self.watchdog_task)
                        self.nursery.start_soon(self.autopull_vault_task)
                    await trio.sleep_forever()
            except Exception as e:
                self.logger.exception("Failure during vault operation")
                await self.app.set_vault_state(self.vault, VaultState.FAILURE)
            finally:
                self.logger.debug("Closed nursery")
                self.nursery = None
            await trio.sleep(10)
