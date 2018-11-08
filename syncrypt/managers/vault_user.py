import logging

from syncrypt.models import VaultUser, Vault, store

logger = logging.getLogger(__name__)


class VaultUserManager:
    model = VaultUser

    def __init__(self, app):
        self.app = app

    def add(self, vault, user_id):
        with store.session() as session:
            session.add(VaultUser(vault_id=vault.id, user_id=user_id))

    def remove(self, vault, user_id):
        raise NotImplementedError()

    def list_for_vault(self, vault):
        with store.session() as session:
            return (
                session.query(VaultUser)
                .filter(self.model.vault_id == vault.id)
                .all()
            )

    async def delete_for_vault(self, vault: Vault) -> None:
        with store.session() as session:
            session.query(self.model).filter(self.model.vault_id == vault.id).delete()

    def find_key(self, vault: Vault, fingerprint) -> VaultUser:
        with store.session() as session:
            return (
                session.query(VaultUser)
                .filter(self.model.vault_id == vault.id)
                .filter(self.model.fingerprint == fingerprint)
                .first()
            )
