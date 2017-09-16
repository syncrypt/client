'This builtin module implements log streaming and log persistence'

import asyncio
import json
import logging
import os.path
import sqlite3
from datetime import datetime
from logging.handlers import BufferingHandler
from logging import StreamHandler

import smokesignal
from aiohttp import web

from syncrypt.api.resources import VaultResource
from syncrypt.api.responses import JSONResponse

logger = logging.getLogger(__name__)


class WebSocketHandler(StreamHandler):
    def __init__(self, ws, app, *args, **kwargs):
        self.ws = ws
        super(WebSocketHandler, self).__init__(*args, **kwargs)
        self.setFormatter(JSONFormatter(app))

    def emit(self, record):
        if not self.ws.closed:
            self.ws.send_str(self.format(record))


class VaultFilter(logging.Filter):
    def __init__(self, vault):
        self._vault = vault

    def filter(self, record):
        return 1 if getattr(record, 'vault_id', None) == self._vault.config.id else 0


class JSONFormatter(logging.Formatter):
    def __init__(self, app):
        self.app = app
        super(JSONFormatter, self).__init__()

    def format(self, record):
        return json.dumps({
            'level': record.levelname,
            'createdAt': record.asctime,
            'message': super(JSONFormatter, self).format(record),
            'vault_id': getattr(record, 'vault_id', None)
        })


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
            d['vault_id'] = row[idx]
        elif name == 'date':
            d['createdAt'] = row[idx]
    return d


def open_database(app):
    filename = os.path.join(app.config.config_dir, 'vault_log.db')
    return sqlite3.connect(filename, detect_types=sqlite3.PARSE_DECLTYPES)


def select_recent_log_items(app, vault_id=None, limit=100, conn=None):
    'return ``limit`` most recent log items'
    if not conn:
        conn = open_database(app)

    conn.row_factory = log_factory
    if vault_id:
        cursor = conn.execute('SELECT * FROM log WHERE vault = ? ORDER BY date DESC LIMIT ?',
                              (vault_id, limit))
    else:
        cursor = conn.execute('SELECT * FROM log ORDER BY date DESC LIMIT ?',
                              (limit, ))
    return cursor.fetchall()


@asyncio.coroutine
def ws_stream_log(request, app, vault_id=None, limit=None, filters=None):
    'Stream Python logs via WebSockets'

    ws = web.WebSocketResponse()
    yield from ws.prepare(request)

    for item in select_recent_log_items(app, vault_id, 100):
        ws.send_str(json.dumps(item))

    root_logger = logging.getLogger()
    wshandler = WebSocketHandler(ws, app)

    if vault_id:
        wshandler.addFilter(VaultFilter(app.find_vault_by_id(vault_id)))

    if filters:
        for fltr in filters:
            wshandler.addFilter(fltr)

    root_logger.addHandler(wshandler)
    while not ws.closed:
        msg = yield from ws.receive()
        logger.debug(msg)
    root_logger.removeHandler(wshandler)

    logger.debug('WebSocket connection closed')


def create_dispatch_log_list(app):
    conn = open_database(app)

    @asyncio.coroutine
    def dispatch_log_list(request):
        vault_id = request.match_info.get('vault_id', None)
        limit = int(request.GET.get('limit', 100))
        return JSONResponse(select_recent_log_items(app, vault_id, limit, conn=conn))

    return dispatch_log_list


def create_dispatch_stream_log(app):
    @asyncio.coroutine
    def dispatch_stream_log(request):
        vault_id = request.match_info.get('vault_id', None)
        limit = int(request.GET.get('limit', 100))
        yield from ws_stream_log(request, app, vault_id=vault_id, limit=limit)

    return dispatch_stream_log


@smokesignal.once('pre_setup')
def pre_setup(app):
    root_logger = logging.getLogger()
    conn = open_database(app)
    conn.execute('''CREATE TABLE IF NOT EXISTS log
                    (date datetime,
                     message text,
                     level text,
                     vault text)''')
    root_logger.addHandler(SqliteHandler(conn=conn, capacity=30))


@smokesignal.on('post_api_initialize')
def post_api_initialize(app, api):
    router = api.web_app.router
    router.add_route('GET', '/v1/vault/{vault_id}/log/', create_dispatch_log_list(app))
    router.add_route('GET', '/v1/vault/{vault_id}/logstream/', create_dispatch_stream_log(app))
    router.add_route('GET', '/v1/log/', create_dispatch_log_list(app))
    router.add_route('GET', '/v1/logstream/', create_dispatch_stream_log(app))
