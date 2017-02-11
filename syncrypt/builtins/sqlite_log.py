import logging
import os.path
import sqlite3
from datetime import datetime
from logging.handlers import BufferingHandler


class SqliteHandler(BufferingHandler):
    def __init__(self, filename, *args, **kwargs):
        super(SqliteHandler, self).__init__(*args, **kwargs)
        self.conn = sqlite3.connect(filename, detect_types=sqlite3.PARSE_DECLTYPES)
        self.conn.execute('''CREATE TABLE IF NOT EXISTS log
                             (date datetime,
                              message text,
                              level text,
                              vault text)''')

    def format(self, record):
        return (datetime.fromtimestamp(record.created),
                record.getMessage(),
                record.levelname,
                record.vault_id if hasattr(record, 'vault_id') else None)

    def flush(self):
        c = self.conn.cursor()
        c.executemany("INSERT INTO log VALUES (?, ?, ?, ?)",
            [self.format(record) for record in self.buffer])
        self.conn.commit()
        super(SqliteHandler, self).flush() # zap the buffer

    def close(self):
        self.conn.commit()


def setup(app):
    root_logger = logging.getLogger()

    filename = os.path.join(app.config.config_dir, 'vault_log.db')

    # Add our SqliteHandler if it hasn't been added yet
    if not any(isinstance(h, SqliteHandler) for h in root_logger.handlers):
        root_logger.addHandler(SqliteHandler(filename=filename, capacity=30))

