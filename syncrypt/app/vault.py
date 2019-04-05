import logging
import os.path
from functools import partial
from typing import Tuple

import trio
from trio_typing import Nursery

from syncrypt.exceptions import SyncryptBaseException
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
    def __init__(self, app, vault):
        self.app = app
        self.vault = vault
        self.nursery = None # type: Nursery
        self.logger = VaultLoggerAdapter(self.vault, logging.getLogger(__name__))
        send_channel, receive_channel = trio.open_memory_channel(128) # type: Tuple[trio.abc.SendChannel, trio.abc.ReceiveChannel]
        self.file_changes_send_channel = send_channel # type: trio.abc.SendChannel
        self.file_changes_receive_channel = receive_channel # type: trio.abc.ReceiveChannel

    async def resync(self):
        assert self.nursery is not None
        self.nursery.start_soon(partial(self.app.sync_vault, self.vault, full=True))

    async def watchdog_task(self):
        self.logger.debug("watchdog_task started")

        async with trio.open_nursery() as nursery:
            watchdog = Watchdog(self.vault.folder,
                event_handler=MemoryChannelEventHandler(self.file_changes_send_channel)
            )
            watchdog.start()
            try:
                await trio.sleep_forever()
            finally:
                await watchdog.stop()

    async def respond_to_file_changes(self):
        self.logger.debug("respond_to_file_changes started")
        async for filechange in self.file_changes_receive_channel:
            # print(filechange)
            if filechange.event_type == 'modified':
                bundle = self.app.bundles.get_bundle_for_relpath(
                        os.path.relpath(filechange.src_path, self.vault.folder),
                        self.vault)
                if bundle is None:
                    self.logger.debug('Ignoring file change in %s', filechange.src_path)
                    continue

                self.app.schedule_push(bundle)

        await trio.sleep_forever()

    async def cancel(self):
        self.nursery.cancel_scope.cancel()

    async def run(self, do_init, do_push, task_status=trio.TASK_STATUS_IGNORED):
        assert self.nursery is None
        async with trio.open_nursery() as nursery:
            self.logger.debug("Opened nursery")
            self.nursery = nursery

            try:
                self.vault.check_existence()
                self.app.identity.assert_initialized()
            except SyncryptBaseException:
                self.logger.exception("Failure during vault initialization")
                await self.app.set_vault_state(self.vault, VaultState.FAILURE)

            task_status.started()

            if do_init:
                await self.app.init_vault(self.vault)

            if do_push:
                await self.app.pull_vault(self.vault, full=do_init)
                await self.app.push_vault(self.vault)

            self.nursery.start_soon(self.respond_to_file_changes)
            self.nursery.start_soon(self.watchdog_task)
            self.logger.debug("Sleeping forever")
            await trio.sleep_forever()
        self.logger.debug("Closed nursery")
        self.nursery = None
