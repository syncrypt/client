
from sqlalchemy import Column, Integer, LargeBinary, String

from .base import Base
from .identity import Identity


class UserVaultKey(Base):
    __tablename__ = 'user_vault_key'

    id = Column(Integer(), primary_key=True)
    vault_id = Column(String(128))
    user_id = Column(String(128)) # aka email
    fingerprint = Column(String(128))
    public_key = Column(LargeBinary(512))

    def get_identity(self, config) -> Identity:
        "Construct an Identity object representing this UserVaultKey"
        return Identity.from_key(self.public_key, config)
