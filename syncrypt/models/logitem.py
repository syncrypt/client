import enum
import logging

from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, String

from .base import Base

logger = logging.getLogger(__name__)


class LogLevel(enum.Enum):
    Debug = "DEBUG"
    Info = "INFO"
    Warning = "WARNING"
    Error = "ERROR"


class LogItem(Base):
    __tablename__ = "logitem"

    # These are for local management
    id = Column(Integer(), primary_key=True)
    local_vault_id = Column(String(128), ForeignKey("vault.id"))

    level = Column(Enum(LogLevel, values_callable=lambda x: [e.value for e in x]))
    created_at = Column(DateTime())
    text = Column(String(250), nullable=True)
