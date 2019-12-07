import logging
import ssl
from typing import List  # pylint: disable=unused-import

import aiohttp
import certifi
import trio_asyncio
from aiohttp.http_exceptions import HttpProcessingError

from .base import BufferedFree, Limit, Sink, Source

logger = logging.getLogger(__name__)


class AiohttpClientSessionMixin:

    def init_client(self, client, headers={}):
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context)
        if client:
            self.client_owned, self.client = False, client
        else:
            self.client_owned, self.client = True, aiohttp.ClientSession(
                connector=conn,
                headers=headers,
                skip_auto_headers=["Content-Type", "User-Agent"],
            )

    async def close_client(self):
        if self.client_owned and not self.client.closed:
            await self.client.close()


DEFAULT_CHUNK_SIZE = 1024 * 10 * 16


class URLReader(Source, AiohttpClientSessionMixin):

    def __init__(self, url, client=None):
        super(URLReader, self).__init__()
        self.url = url
        self.response = None
        self.init_client(client)

    @trio_asyncio.aio_as_trio
    async def read(self, count=-1):
        if self._eof:
            return b""
        if self.response is None:
            self.response = await self.client.get(self.url)
            self.response.raise_for_status()
        if count == -1:
            count = DEFAULT_CHUNK_SIZE
        buf = await self.response.content.read(count)
        if len(buf) == 0:
            await self._close()
        return buf

    async def _close(self):
        self._eof = True
        if not self.response is None:
            await self.response.release()
            self.response = None
        await self.close_client()

    @trio_asyncio.aio_as_trio
    async def close(self):
        await self._close()


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

    @trio_asyncio.aio_as_trio
    async def read(self, count=-1):
        if self._done:
            return b""
        if self.response is None:

            @trio_asyncio.trio_as_aio
            async def read_from_input():
                assert self.input is not None
                return (await self.input.read())

            async def feed_http_upload():
                while True:
                    buf = await read_from_input()
                    if len(buf) == 0:
                        break
                    yield buf
                    self.bytes_written += len(buf)

            logger.debug('HTTP PUT %s', self.url)

            self.response = await self.client.put(
                self.url,
                data=feed_http_upload(),
                raise_for_status=True,
                headers={} if self.size is None else {"Content-Length": str(self.size)},
            )
        content = await self.response.read()
        await self.response.release()
        if not self.response.status in (200, 201, 202):
            raise HttpProcessingError(
                code=self.response.status,
                message=self.response.reason,
                headers=self.response.headers,
            )
        self._done = True
        if "ETAG" in self.response.headers:
            self.etag = self.response.headers["ETAG"][1:-1]
        return content

    @trio_asyncio.aio_as_trio
    async def close(self):
        self._done = True
        if not self.response is None:
            await self.response.release()
            self.response = None
        await self.close_client()


class ChunkedURLWriter(Sink, AiohttpClientSessionMixin):
    """
    The ChunkedURLWriter will instantiate an URLWriter for each URL given to
    it.
    """

    def __init__(self, urls, chunksize, total_size=None, client=None):
        super(ChunkedURLWriter, self).__init__()
        self._urls = urls
        self._chunksize = chunksize
        self._url_idx = 0
        self.init_client(client)
        self.bytes_written = 0
        self.total_size = total_size
        self.etags = []  # type: List[str]

    def add_input(self, input):
        self.input = input >> BufferedFree()

    async def read(self, count=-1):
        assert self.input is not None
        if self._url_idx >= len(self._urls):
            return b""
        url = self._urls[self._url_idx]
        logger.debug("Uploading to: %s (max. %d bytes)", url, self._chunksize)
        size = (
            None
            if self.total_size is None
            else min(self.total_size - self.bytes_written, self._chunksize)
        )
        writer = (
            self.input
            >> Limit(self._chunksize)
            >> URLWriter(url, size=size, client=self.client)
        )
        result = await writer.readall()
        self.etags.append(writer.etag)
        self.bytes_written += writer.bytes_written
        self._url_idx += 1
        return result or b"<empty response>"

    @trio_asyncio.aio_as_trio
    async def close(self):
        await self.close_client()
