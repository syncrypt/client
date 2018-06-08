import asyncio
import logging

from sqlalchemy.orm.exc import NoResultFound

from syncrypt.models import UserVaultKey, store

logger = logging.getLogger(__name__)

class UserVaultKeyManager:
    model = UserVaultKey

    def list_for_vault(self, vault):
        with store.session() as session:
            return session.query(UserVaultKey)\
                    .filter(UserVaultKey.vault_id==vault.config.id).all()
