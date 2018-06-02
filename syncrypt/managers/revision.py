import asyncio
import logging
from datetime import timezone

import iso8601
from sqlalchemy import desc
from sqlalchemy.orm.exc import NoResultFound

from syncrypt.exceptions import InvalidRevision
from syncrypt.models import Bundle, Revision, RevisionOp, UserVaultKey, Vault, store
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
                rev.user_id = server_info['email'].decode(vault.config.encoding)
                session.add(rev)
                if count % 20 == 0:
                    session.commit()
                    session.expunge_all()

    async def apply(self, revision: Revision, vault: Vault):

        revision.assert_valid()

        # 1. Check preconditions for this to be a valid revision (current revision must be parent)
        if vault.revision != revision.parent_id:
            raise InvalidRevision("parent does not match: {0}".format(revision.parent_id))

        with store.session() as session:

            # 2. Check if signing user's key is in the user vault key list
            # TODO

            # 3. Verify transaction signature
            # TODO

            # 4. Based on the revision type, perform an action to our state of the vault
            logger.debug("Applying %s (%s)", revision.operation, revision.id)

            if revision.operation == RevisionOp.CreateVault:
                session.add(UserVaultKey(vault_id=revision.vault_id, user_id=revision.user_id,
                                         fingerprint=revision.user_fingerprint,
                                         public_key=revision.public_key))
                session.commit()
            elif revision.operation == RevisionOp.Upload:
                # TODO: get relpath from revision.metadata
                session.add(Bundle(vault_id=revision.vault_id, store_hash=revision.file_hash))
                session.commit()
            else:
                raise NotImplementedError()

            # 5. Store the revision in config and db
            vault.update_revision(revision)
