import asyncio
import logging

from sqlalchemy.orm.exc import NoResultFound

from syncrypt.models import Vault, store

logger = logging.getLogger(__name__)


class VaultManager:
    model = Vault

    def __init__(self, app):
        self.app = app

    async def delete(self, id):
        with store.session() as session:
            return session.query(self.model).filter(self.model.id == id).delete()
