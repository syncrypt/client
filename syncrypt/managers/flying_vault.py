import logging

import iso8601
import trio
from sqlalchemy.orm.exc import NoResultFound
from syncrypt.exceptions import InvalidAuthentification
from syncrypt.models import FlyingVault, store

logger = logging.getLogger(__name__)


class FlyingVaultManager:
    model = FlyingVault

    def __init__(self, app):
        self.app = app

    def get_or_create_by_id(self, session, id):
        try:
            return session.query(self.model).filter(self.model.id == id).one()
        except NoResultFound:
            return self.model(id=id)

    def get(self, id):
        with store.session() as session:
            return session.query(FlyingVault).filter(FlyingVault.id == id).one()

    def all(self):
        with store.session() as session:
            return session.query(FlyingVault).all()

    async def update(self):
        "Update list from remote"
        logger.info("Updating flying vaults...")
        try:
            backend = await self.app.open_backend()
        except InvalidAuthentification:
            logger.info("No login information found, skipping update.")
            return

        # Make a map from vault id -> vault info
        # Maybe we can use VaultManager in the future?
        v_infos = {v["id"].decode(): v for v in (await backend.list_vaults())}

        with store.session() as session:
            lst = await backend.list_vaults_for_identity(self.app.identity)
            for (vault, user_vault_key, encrypted_metadata) in lst:

                await trio.sleep(0.001)

                vault_id = vault["id"].decode("utf-8")

                logger.debug(
                    "Received vault: %s (with%s metadata)",
                    vault_id,
                    "" if encrypted_metadata else "out",
                )

                if encrypted_metadata:
                    metadata = await self.app._decrypt_metadata(
                        encrypted_metadata, user_vault_key
                    )
                else:
                    metadata = None

                v_info = v_infos.get(vault_id)

                if v_info is None:
                    logger.warning("No information for vault: %s, ignoring.", vault_id)
                    continue

                # list_vaults should not return a dict, but a parsed
                # instance of vault or similar
                modification_date_str = v_info.get("modification_date")
                if isinstance(modification_date_str, bytes):
                    modification_date_str = modification_date_str.decode()
                modification_date = iso8601.parse_date(modification_date_str)

                fv = self.get_or_create_by_id(session, vault_id)
                fv.byte_size = v_info.get("byte_size", 0)
                fv.user_count = v_info.get("user_count", 0)
                fv.file_count = v_info.get("file_count", 0)
                fv.revision_count = v_info.get("revision_count", 0)
                fv.modification_date = modification_date
                fv.vault_metadata = metadata

                session.add(fv)
