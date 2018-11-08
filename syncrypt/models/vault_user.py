
from sqlalchemy import Column, Integer, String

from .base import Base


class VaultUser(Base):
    __tablename__ = 'vault_user'

    id = Column(Integer(), primary_key=True)
    vault_id = Column(String(128))
    user_id = Column(String(128)) # aka email
