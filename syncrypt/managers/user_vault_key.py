import asyncio
import logging

from syncrypt.models import UserVaultKey, Vault, store

logger = logging.getLogger(__name__)


class UserVaultKeyManager:
    model = UserVaultKey

    def __init__(self, app):
        self.app = app

    def list_for_vault(self, vault):
        with store.session() as session:
            return (
                session.query(UserVaultKey)
                .filter(UserVaultKey.vault_id == vault.id)
                .all()
            )

    async def delete_for_vault(self, vault: Vault) -> None:
        with store.session() as session:
            session.query(self.model).filter(self.model.vault_id == vault.config.id).delete()

    def find_key(self, vault: Vault, fingerprint) -> UserVaultKey:
        with store.session() as session:
            return (
                session.query(UserVaultKey)
                .filter(UserVaultKey.vault_id == vault.id)
                .filter(UserVaultKey.fingerprint == fingerprint)
                .first()
            )
