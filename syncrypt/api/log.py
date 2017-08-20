import asyncio
import json
import logging

from aiohttp import web
from .resources import VaultResource

logger = logging.getLogger(__name__)


class WebSocketHandler(logging.StreamHandler):
    def __init__(self, ws, api, *args, **kwargs):
        self.ws = ws
        self.app = api.app
        super(WebSocketHandler, self).__init__(*args, **kwargs)

    def emit(self, record):
        if not self.ws.closed:
            vault_uri = None

            if hasattr(record, 'vault_id'):
                vault_resource = VaultResource(self.app)
                vault = vault_resource.find_vault_by_id(record.vault_id)
                vault_uri = vault_resource.get_resource_uri(vault)

            self.ws.send_str(json.dumps({
                'level': record.levelname,
                'time': record.asctime,
                'text': self.format(record),
                'vault': vault_uri
            }))


@asyncio.coroutine
def ws_global_log(api, request):

    ws = web.WebSocketResponse()
    yield from ws.prepare(request)

    root_logger = logging.getLogger()
    wshandler = root_logger.addHandler(WebSocketHandler(ws, api))

    while not ws.closed:
        msg = yield from ws.receive()
        logger.debug(msg)
        #if msg.type == aiohttp.WSMsgType.ERROR:
        #    logger.warn('ws connection closed with exception %s', ws.exception())
        #    break

    logger.debug('websocket connection closed')
    root_logger.removeHandler(wshandler)

