import os.path
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from syncrypt.models.base import Base

from .bundle import Bundle, VirtualBundle
from .flying_vault import FlyingVault
from .identity import Identity, IdentityState
from .vault import Vault, VaultState


class Store:
    def __init__(self):
        pass

    def init(self, config):
        engine = config.get('store.engine')
        db = os.path.join(config.config_dir, config.get('store.path'))
        uri = '{engine}:///{db}'.format(engine=engine, db=db)
        engine = create_engine(uri, echo=True)
        #engine = create_engine('sqlite:///:memory:', echo=True)
        self._session = sessionmaker(bind=engine, expire_on_commit=False)
        Base.metadata.create_all(engine)

    @contextmanager
    def session(self, expunge_objects=True):
        """Provide a transactional scope around a series of operations."""
        session = self._session()
        try:
            yield session
            session.commit()
        except:
            session.rollback()
            raise
        finally:
            if expunge_objects:
                session.expunge_all()
            session.close()

store = Store()
