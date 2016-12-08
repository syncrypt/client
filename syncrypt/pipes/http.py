import logging
import sys
import os.path
import shutil

import aiofiles
import asyncio

from .base import Pipe, Sink, Source

logger = logging.getLogger(__name__)


class URLReader(Pipe):
    def __init__(self, url):
        super(URLReader, self).__init__()
        self.url = url

    @asyncio.coroutine
    def close(self):
        # Do NOT close handle
        pass
