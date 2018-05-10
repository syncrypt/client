import asyncio
import logging
from datetime import timezone

import iso8601
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy import desc

from syncrypt.models import Revision, store
from syncrypt.models.bundle import VirtualBundle
from syncrypt.pipes import Once

logger = logging.getLogger(__name__)

class RevisionManager:
    model = Revision

    def __init__(self, app):
        self.app = app

    def get_or_create_by_id(self, session, id):
        try:
            return session.query(self.model)\
                    .filter(self.model.id==id).one()
        except NoResultFound:
            return self.model(id=id)

    def list_for_vault(self, vault):
        with store.session() as session:
            return session.query(Revision)\
                    .filter(Revision.vault_id==vault.config.id).all()

    async def update_for_vault(self, vault):
        with store.session() as session:
            try:
                latest_rev = session.query(self.model)\
                        .filter(Revision.vault_id==vault.config.id)\
                        .order_by(desc(Revision.created_at)).limit(1).one()
            except NoResultFound:
                latest_rev = None

            queue = await vault.backend.changes(latest_rev and latest_rev.id, None, verbose=True)
            log_items = []
            count = 0
            while True:
                item = await queue.get()
                if item is None:
                    break
                count += 1
                store_hash, metadata, server_info = item
                bundle = VirtualBundle(None, vault, store_hash=store_hash)
                await bundle.write_encrypted_metadata(Once(metadata))

                rev_id = server_info['id'].decode(vault.config.encoding)
                rev = self.get_or_create_by_id(session, rev_id)
                rev.vault_id = vault.config.id
                rev.created_at = \
                        iso8601.parse_date(server_info['created_at'].decode())\
                            .astimezone(timezone.utc)\
                            .replace(tzinfo=None)
                rev.path = bundle.relpath
                rev.operation = server_info['operation'].decode(vault.config.encoding)
                rev.user_email = server_info['email'].decode(vault.config.encoding)
                session.add(rev)
                if count % 20 == 0:
                    session.commit()
                    session.expunge_all()
