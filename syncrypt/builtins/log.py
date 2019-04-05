"This builtin module implements log streaming and log persistence"
import asyncio
import json
import logging
from datetime import datetime, timezone
from logging import StreamHandler
from logging.handlers import BufferingHandler
from typing import Any, Dict

import smokesignal
from aiohttp import web
from syncrypt.api.responses import JSONResponse
from syncrypt.models import LogItem, store
from syncrypt.utils.format import datetime_format_iso8601
from tzlocal import get_localzone

logger = logging.getLogger(__name__)
MAX_ITEMS_LOGGING_QUEUE = 4096
MAX_ITEMS_BEFORE_DRAIN = 64


local_tz = get_localzone()


def logitem_to_json(logitem: LogItem) -> Dict[str, Any]:
    return {
            "level": logitem.level,
            "created_at": datetime_format_iso8601(logitem.created_at),
            "message": logitem.text,
            "vault_id": logitem.local_vault_id
            }


class QueueHandler(StreamHandler):

    def __init__(self, into: asyncio.Queue, formatter, *args, **kwargs) -> None:
        super(QueueHandler, self).__init__(*args, **kwargs)
        self.setFormatter(formatter)
        self.into = into

    def emit(self, record):
        try:
            self.into.put_nowait(self.format(record))
        except asyncio.QueueFull:
            pass


class VaultFilter(logging.Filter):

    def __init__(self, vault):
        self._vault = vault

    def filter(self, record):
        return 1 if getattr(record, "vault_id", None) == self._vault.id else 0


class JSONFormatter(logging.Formatter):

    def __init__(self, app):
        self.app = app
        super(JSONFormatter, self).__init__()

    def format(self, record):
        created_at = datetime.fromtimestamp(record.created, tz=local_tz).astimezone(timezone.utc)
        return json.dumps(
            {
                "level": getattr(record, "levelname", None),
                "created_at": datetime_format_iso8601(created_at),
                "message": super(JSONFormatter, self).format(record),
                "vault_id": getattr(record, "vault_id", None),
            }
        )


class SqliteHandler(BufferingHandler):

    def __init__(self, session, *args, **kwargs):
        self.session = session
        super(SqliteHandler, self).__init__(*args, **kwargs)

    def format(self, record):
        return LogItem(
            created_at=datetime.fromtimestamp(record.created, tz=local_tz).astimezone(timezone.utc),
            text=record.getMessage(),
            level=record.levelname,
            local_vault_id=getattr(record, "vault_id", None)
        )

    def flush(self):
        self.session.bulk_save_objects([
            self.format(rec) for rec in self.buffer
        ])
        self.session.commit()
        super(SqliteHandler, self).flush()  # zap the buffer

    def close(self):
        self.session.close()


def recent_log_items(app, vault_id=None, limit=100, session=None):
    "return ``limit`` most recent log items"
    objects = session.query(LogItem)
    if vault_id:
        objects = objects.filter(LogItem.local_vault_id == vault_id)
    return objects.limit(limit)


async def ws_stream_log(request, ws, app, vault_id=None, limit=None, filters=None):
    "Stream Python logs via WebSockets"
    await ws.prepare(request)
    with store.session() as session:
        for logitem in recent_log_items(app, vault_id, 100, session):
            await ws.send_str(JSONResponse.encode_body(logitem_to_json(logitem)).decode('utf-8'))
        root_logger = logging.getLogger()
        queue = asyncio.Queue(maxsize=MAX_ITEMS_LOGGING_QUEUE)  # type: asyncio.Queue
        handler = QueueHandler(queue, JSONFormatter(app))
        if vault_id:
            handler.addFilter(VaultFilter(app.find_vault_by_id(vault_id)))
        if filters:
            for fltr in filters:
                handler.addFilter(fltr)

        async def writer():
            while not ws.closed:
                item = await queue.get()
                try:
                    # Send the item and also try to get up to MAX_ITEMS_BEFORE_DRAIN items from the
                    # queue before draining the connection
                    for _ in range(MAX_ITEMS_BEFORE_DRAIN):
                        await ws.send_str(str(item))
                        item = queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass

        async def reader():
            while not ws.closed:
                await ws.receive()

        root_logger.addHandler(handler)
        writer_future = asyncio.ensure_future(writer())
        await reader()
        root_logger.removeHandler(handler)
        writer_future.cancel()


def create_dispatch_log_list(app):
    async def dispatch_log_list(request):
        vault_id = request.match_info.get("vault_id", None)
        limit = int(request.query.get("limit", 100))
        with store.session() as session:
            return JSONResponse(
                [logitem_to_json(logitem) for logitem in
                    recent_log_items(app, vault_id, limit, session)]
            )

    return dispatch_log_list


def create_dispatch_stream_log(app):
    async def dispatch_stream_log(request):
        vault_id = request.match_info.get("vault_id", None)
        limit = int(request.query.get("limit", 100))
        ws = web.WebSocketResponse()
        logger.debug("WebSocket connection opened for %s", request.path)
        await ws_stream_log(request, ws, app, vault_id=vault_id, limit=limit)
        logger.debug("WebSocket connection closed for %s", request.path)
        return ws

    return dispatch_stream_log


@smokesignal.once("pre_setup")
def pre_setup(app):
    session = store._session()
    root_logger = logging.getLogger()
    root_logger.addHandler(SqliteHandler(session=session, capacity=30))


@smokesignal.on("post_api_initialize")
def post_api_initialize(app, api):
    router = api.web_app.router
    router.add_route("GET", "/v1/vault/{vault_id}/log/", create_dispatch_log_list(app))
    router.add_route(
        "GET", "/v1/vault/{vault_id}/logstream/", create_dispatch_stream_log(app)
    )
    router.add_route("GET", "/v1/log/", create_dispatch_log_list(app))
    router.add_route("GET", "/v1/logstream/", create_dispatch_stream_log(app))
