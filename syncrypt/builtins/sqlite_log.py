import asyncio
import logging
import os.path
import sqlite3
from datetime import datetime
from logging.handlers import BufferingHandler

import smokesignal

from syncrypt.api.responses import JSONResponse
from syncrypt.api.resources import VaultResource


class SqliteHandler(BufferingHandler):
    def __init__(self, conn, *args, **kwargs):
        self.conn = conn
        super(SqliteHandler, self).__init__(*args, **kwargs)

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


def create_dispatch_log_list(conn, app):
    vault_resource = VaultResource(app)

    # Change connection's row_factory to a log entry so we can
    # plug the fetch results directly into a JSONResponse
    # https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.row_factory
    def log_factory(cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            name = col[0]
            if name in ('level', 'message'):
                d[name] = row[idx]
            elif name == 'vault':
                vault = vault_resource.find_vault_by_id(row[idx])
                d[name] = vault_resource.get_resource_uri(vault)
            elif name == 'date':
                d['time'] = row[idx]
        return d
    conn.row_factory = log_factory

    #def row_to_log(row):
    #    if 'vault' in row:
    #        vault_resource = VaultResource(app)
    #        vault = vault_resource.find_vault_by_id(row['vault'])
    #        vault_uri = vault_resource.get_resource_uri(vault)
    #    else:
    #        vault_uri = None

    #return {
    #    'level': row['level'],
    #    'time': row['date'],
    #    'message': row['message'],
    #    'vault': vault_uri
    #}


    @asyncio.coroutine
    def dispatch_log_list(request):
        cursor = conn.execute('''
                SELECT * FROM log
                    WHERE vault = ?
                    ORDER BY date DESC
                    LIMIT 100''',
                (request.match_info['vault_id'], ))
        return JSONResponse(cursor.fetchall())

    return dispatch_log_list


@smokesignal.once('pre_setup')
def pre_setup(app):
    root_logger = logging.getLogger()
    filename = os.path.join(app.config.config_dir, 'vault_log.db')
    conn = sqlite3.connect(filename, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.execute('''CREATE TABLE IF NOT EXISTS log
                    (date datetime,
                     message text,
                     level text,
                     vault text)''')
    root_logger.addHandler(SqliteHandler(conn=conn, capacity=30))


@smokesignal.on('post_api_initialize')
def post_api_initialize(app, api):
    filename = os.path.join(app.config.config_dir, 'vault_log.db')
    conn = sqlite3.connect(filename, detect_types=sqlite3.PARSE_DECLTYPES)
    router = api.web_app.router
    router.add_route('GET', '/v1/vault/{vault_id}/log/',
                     create_dispatch_log_list(conn, app))

