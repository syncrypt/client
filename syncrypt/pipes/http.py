import logging
import sys
import os.path
import shutil
import aiohttp

import aiofiles
import asyncio

from .base import Pipe, Sink, Source, Limit

logger = logging.getLogger(__name__)

class URLReader(Source):
    def __init__(self, url, client=None):
        super(URLReader, self).__init__()
        self.url = url
        if client:
            self.client_owned, self.client = False, client
        else:
            self.client_owned, self.client = True, aiohttp.ClientSession()
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
            yield from self.response.release()
            self.response = None
        if self.client_owned and not self.client.closed:
            yield from self.client.close()

class URLWriter(Sink):
    def __init__(self, url, client=None):
        super(URLWriter, self).__init__()
        self.url = url
        if client:
            self.client_owned, self.client = False, client
        else:
            self.client_owned, self.client = True, aiohttp.ClientSession()
        self._done = False
        self.response = None

    @asyncio.coroutine
    def read(self, count=-1):
        if self._done:
            return b''
        if self.response is None:
            self.response = yield from self.client.put(self.url,
                    data=self.feed_http_upload())
        content = yield from self.response.read()
        yield from self.response.release()
        self._done = True
        return content

    @asyncio.coroutine
    def feed_http_upload(self):
        while True:
            buf = (yield from self.input.read())
            if len(buf) == 0:
                break
            yield buf

    @asyncio.coroutine
    def close(self):
        self._done = True
        if not self.response is None:
            yield from self.response.release()
            self.response = None
        if self.client_owned and not self.client.closed:
            yield from self.client.close()

class ChunkedURLWriter(Sink):
    '''
    The ChunkedURLWriter will instantiate an URLWriter for each URL given to
    it.
    '''
    def __init__(self, urls, chunksize, client=None):
        super(ChunkedURLWriter, self).__init__()
        self.client = aiohttp.ClientSession() if client is None else client
        self._urls = urls
        self._chunksize = chunksize
        self._url_idx = 0

    @asyncio.coroutine
    def read(self, count=-1):
        if self._url_idx >= len(self._urls):
            return b''
        url = self._urls[self._url_idx]
        writer = self.input >> Limit(self._chunksize) >> URLWriter(url, client=self.client)
        result = (yield from writer.readall())
        self._url_idx = self._url_idx + 1
        return result

