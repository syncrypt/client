import asyncio
import logging

from aiohttp import web

logger = logging.getLogger(__name__)


class WebSocketHandler(logging.StreamHandler):
    def __init__(self, ws, *args, **kwargs):
        self.ws = ws
        super(WebSocketHandler, self).__init__(*args, **kwargs)

    def emit(self, record):
        if not self.ws.closed:
            self.ws.send_str(str(record))


@asyncio.coroutine
def ws_global_log(request):

    ws = web.WebSocketResponse()
    yield from ws.prepare(request)

    root_logger = logging.getLogger()
    wshandler = root_logger.addHandler(WebSocketHandler(ws))

    ws.send_str('Hi lol')

    while not ws.closed:
        msg = yield from ws.receive()
        logger.debug(msg)
        #if msg.type == aiohttp.WSMsgType.ERROR:
        #    logger.warn('ws connection closed with exception %s', ws.exception())
        #    break

    logger.debug('websocket connection closed')
    root_logger.removeHandler(wshandler)

    return ws

