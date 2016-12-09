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
        return (yield from self.response.content.read(count))

    @asyncio.coroutine
    def close(self):
        # Do NOT close handle
        pass
