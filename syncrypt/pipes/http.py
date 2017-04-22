import asyncio
import logging
import os.path
import shutil
import ssl
import sys

import aiofiles
import aiohttp
import certifi

from .base import BufferedFree, Limit, Pipe, Sink, Source

logger = logging.getLogger(__name__)

class AiohttpClientSessionMixin():
    def init_client(self, client, headers={}):
        sslcontext = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl_context=sslcontext)
        if client:
            self.client_owned, self.client = False, client
        else:
            self.client_owned, self.client = True, aiohttp.ClientSession(
                    connector=conn,
                    headers=headers,
                    skip_auto_headers=["Content-Type", "User-Agent"]
                    )

    @asyncio.coroutine
    def close_client(self):
        if self.client_owned and not self.client.closed:
            yield from self.client.close()


DEFAULT_CHUNK_SIZE = 1024*10*16


class URLReader(Source, AiohttpClientSessionMixin):
    def __init__(self, url, client=None):
        super(URLReader, self).__init__()
        self.url = url
        self.response = None
        self.init_client(client)

    @asyncio.coroutine
    def read(self, count=-1):
        if self._eof:
            return b''
        if self.response is None:
            self.response = yield from self.client.get(self.url)
        if count == -1: count = DEFAULT_CHUNK_SIZE
        buf = (yield from self.response.content.read(count))
        if len(buf) == 0:
            yield from self.close()
        return buf

    @asyncio.coroutine
    def close(self):
        self._eof = True
        if not self.response is None:
            yield from self.response.release()
            self.response = None
        yield from self.close_client()


class URLWriter(Sink, AiohttpClientSessionMixin):
    def __init__(self, url, size=None, client=None):
        super(URLWriter, self).__init__()
        self.url = url
        self._done = False
        self.response = None
        self.bytes_written = 0
        self.size = size
        self.etag = None
        self.init_client(client)

    @asyncio.coroutine
    def read(self, count=-1):
        if self._done:
            return b''
        if self.response is None:
            self.response = yield from self.client.put(self.url,
                    data=self.feed_http_upload(),
                    headers={} if self.size is None else {'Content-Length': str(self.size)})
        content = yield from self.response.read()
        yield from self.response.release()
        if not self.response.status in (200, 201, 202):
            raise aiohttp.HttpProcessingError(
                code=self.response.status, message=self.response.reason,
                headers=self.response.headers)
        self._done = True
        if 'ETAG' in self.response.headers:
            self.etag = self.response.headers['ETAG'][1:-1]
        return content

    @asyncio.coroutine
    def feed_http_upload(self):
        while True:
            buf = (yield from self.input.read())
            if len(buf) == 0:
                break
            yield buf
            self.bytes_written += len(buf)

    @asyncio.coroutine
    def close(self):
        self._done = True
        if not self.response is None:
            yield from self.response.release()
            self.response = None
        yield from self.close_client()

class ChunkedURLWriter(Sink, AiohttpClientSessionMixin):
    '''
    The ChunkedURLWriter will instantiate an URLWriter for each URL given to
    it.
    '''
    def __init__(self, urls, chunksize, total_size=None, client=None):
        super(ChunkedURLWriter, self).__init__()
        self._urls = urls
        self._chunksize = chunksize
        self._url_idx = 0
        self.init_client(client)
        self.bytes_written = 0
        self.total_size = total_size
        self.etags = []

    def add_input(self, input):
        self.input = input >> BufferedFree()

    @asyncio.coroutine
    def read(self, count=-1):
        if self._url_idx >= len(self._urls):
            return b''
        url = self._urls[self._url_idx]
        logger.debug('Uploading to: %s (max. %d bytes)', url, self._chunksize)
        size = None if self.total_size is None else min(self.total_size - self.bytes_written, self._chunksize)
        writer = self.input >> Limit(self._chunksize) >> URLWriter(url, size=size, client=self.client)
        result = (yield from writer.readall())
        self.etags.append(writer.etag)
        self.bytes_written += writer.bytes_written
        self._url_idx += 1
        return result or b'<empty response>'

    @asyncio.coroutine
    def close(self):
        yield from self.close_client()
