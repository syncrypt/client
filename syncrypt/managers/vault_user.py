import logging

from syncrypt.models import VaultUser, Vault, store
from sqlalchemy import exists as sa_exists, and_

logger = logging.getLogger(__name__)


class VaultUserManager:
    model = VaultUser

    def __init__(self, app):
        self.app = app

    def add(self, vault: Vault, user_id: str):
        with store.session() as session:
            session.add(VaultUser(vault_id=vault.id, user_id=user_id))

    def remove(self, vault: Vault, user_id: str):
        with store.session() as session:
            return (
                session
                    .query(self.model)
                    .filter(self.model.vault_id == vault.id, self.model.user_id == user_id)
                    .delete()
            )

    def list_for_vault(self, vault: Vault):
        with store.session() as session:
            return (
                session.query(self.model)
                .filter(self.model.vault_id == vault.id)
                .all()
            )

    def exists(self, vault: Vault, user_id: str) -> bool:
        with store.session() as session:
            return (
                session.query(sa_exists().where(
                    and_(self.model.vault_id == vault.id, self.model.user_id == user_id)
                )).scalar()
            )

    async def delete_for_vault(self, vault: Vault) -> None:
        with store.session() as session:
            session.query(self.model).filter(self.model.vault_id == vault.id).delete()

    def find_key(self, vault: Vault, fingerprint) -> VaultUser:
        with store.session() as session:
            return (
                session.query(self.model)
                .filter(self.model.vault_id == vault.id)
                .filter(self.model.fingerprint == fingerprint)
                .first()
            )
