import logging
import sys
import os.path
import shutil
import aiohttp

import aiofiles
import asyncio

from .base import Pipe, Sink, Source

logger = logging.getLogger(__name__)


class URLReader(Pipe):
    def __init__(self, url):
        super(URLReader, self).__init__()
        self.url = url
        self.client = aiohttp.ClientSession()
        self.response = None

    @asyncio.coroutine
    def read(self, count=-1):
        if self.response is None:
            self.response = yield from self.client.get(self.url)
        buf = (yield from self.response.content.read(count))
        if len(buf) == 0:
            yield from self.close()
        return buf

    @asyncio.coroutine
    def close(self):
        if not self.response is None:
            yield from self.response.close()
            self.response = None
