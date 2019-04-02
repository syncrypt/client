import logging
from functools import partial

import trio
from trio_typing import Nursery

from syncrypt.exceptions import SyncryptBaseException
from syncrypt.models import Vault, VaultState


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

    async def resync(self):
        assert self.nursery is not None
        self.nursery.start_soon(partial(self.app.sync_vault, self.vault, full=True))

    async def cancel(self):
        self.nursery.cancel_scope.cancel()

    async def run(self, do_init, do_push):
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

            if do_init:
                await self.app.init_vault(self.vault)

            if do_push:
                await self.app.pull_vault(self.vault, full=do_init)
                await self.app.push_vault(self.vault)

            self.logger.debug("Sleeping forever")
            await trio.sleep_forever()
        self.logger.debug("Closed nursery")
        self.nursery = None
