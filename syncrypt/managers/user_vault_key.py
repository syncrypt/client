import asyncio
import logging

from sqlalchemy.orm.exc import NoResultFound

from syncrypt.models import UserVaultKey, store

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

    def is_key_in_vault(self, vault, fingerprint):
        with store.session() as session:
            return (
                session.query(UserVaultKey)
                .filter(UserVaultKey.fingerprint == fingerprint)
                .count()
                > 0
            )
