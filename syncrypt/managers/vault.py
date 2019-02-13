import logging

from syncrypt.models import Vault, store

logger = logging.getLogger(__name__)


class VaultManager:
    model = Vault

    def __init__(self, app):
        self.app = app

    async def delete(self, id):
        with store.session() as session:
            return session.query(self.model).filter(self.model.id == id).delete()

    async def reset(self, vault: Vault):
        with store.session() as session:
            session.add(vault)
            vault.revision_count = 0
            vault.file_count = 0
            vault.user_count = 0
            session.commit()
