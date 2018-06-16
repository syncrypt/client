import asyncio
import logging

from sqlalchemy.orm.exc import NoResultFound

from syncrypt.models import Bundle, Vault, store

logger = logging.getLogger(__name__)

class BundleManager:
    model = Bundle

    def __init__(self, app):
        self.app = app

    async def download_bundles_for_vault(self, vault):
        """return an iterator of all bundles in the vault that possible require download"""
        with store.session() as session:
            lst = list(session.query(Bundle).filter(Bundle.vault==vault).all())
            for bundle in lst:
                bundle.vault = vault
            return lst

    async def get_bundle(self, vault: Vault, file_hash: str) -> Bundle:
        """return an iterator of all bundles in the vault that possible require download"""
        with store.session() as session:
            return session.query(Bundle).filter(Bundle.vault==vault,
                    Bundle.store_hash==file_hash).one()
