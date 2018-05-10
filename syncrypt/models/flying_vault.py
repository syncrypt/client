import json
import logging

import sqlalchemy.types as types
from sqlalchemy import Column, Integer, String, orm
from sqlalchemy import types as types

from .base import Base

logger = logging.getLogger(__name__)


class TextJSON(types.TypeDecorator):
    """Stores and retrieves JSON as TEXT."""

    impl = types.TEXT

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value


JSON = types.JSON().with_variant(TextJSON, "sqlite")


class FlyingVault(Base):
    __tablename__ = "flying_vault"

    id = Column(String(128), primary_key=True)
    byte_size = Column(Integer())
    file_count = Column(Integer())
    modification_date = Column(String(255))  # date?
    revision_count = Column(Integer())
    user_count = Column(Integer())
    vault_metadata = Column(JSON)
