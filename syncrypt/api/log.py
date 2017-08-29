import asyncio
import json
import logging

from aiohttp import web

from .resources import VaultResource

logger = logging.getLogger(__name__)


class WebSocketHandler(logging.StreamHandler):
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
        vault_uri = None

        if hasattr(record, 'vault_id'):
            vault_resource = VaultResource(self.app)
            vault = vault_resource.find_vault_by_id(record.vault_id)
            vault_uri = vault_resource.get_resource_uri(vault)

        return json.dumps({
            'level': record.levelname,
            'time': record.asctime,
            'message': super(JSONFormatter, self).format(record),
            'vault': vault_uri
        })


@asyncio.coroutine
def ws_stream_log(request, app, filters=[]):
    'Stream Python logs via WebSockets'

    ws = web.WebSocketResponse()
    yield from ws.prepare(request)

    root_logger = logging.getLogger()
    wshandler = WebSocketHandler(ws, app)
    for fltr in filters:
        wshandler.addFilter(fltr)

    root_logger.addHandler(wshandler)
    while not ws.closed:
        msg = yield from ws.receive()
        logger.debug(msg)
    root_logger.removeHandler(wshandler)

    logger.debug('WebSocket connection closed')


