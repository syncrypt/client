from sqlalchemy import Column, Integer, String, DateTime, Binary, LargeBinary, ForeignKey
from enum import Enum
from .base import Base


class UserVaultKey(Base):
    __tablename__ = 'user_vault_key'

    id = Column(Integer(), primary_key=True)
    vault_id = Column(String(128))
    user_id = Column(String(128)) # aka email
    fingerprint = Column(String(128))
    public_key = Column(Binary(512))
