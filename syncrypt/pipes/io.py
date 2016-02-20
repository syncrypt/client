import os.path

import aiofiles
import asyncio

from .base import Pipe, Sink, Source


class StreamReader(Pipe):
    def __init__(self, reader):
        super(StreamReader, self).__init__()
        self.input = reader

    @asyncio.coroutine
    def close(self):
        # Do NOT close handle
        pass

class FileReader(Source):
    # simple wrapper for aiofiles
    def __init__(self, filename):
        self.filename = filename
        self.handle = None
        super(FileReader, self).__init__()

    @asyncio.coroutine
    def read(self, count=-1):
        if self.handle is None and not self._eof:
            self.handle = yield from aiofiles.open(self.filename, 'rb')
        return (yield from self.handle.read(count))

    @asyncio.coroutine
    def close(self):
        if self.handle:
            yield from self.handle.close()

class FileWriter(Sink):
    # simple wrapper for aiofiles
    def __init__(self, filename, create_dirs=False):
        self.filename = filename
        self.handle = None
        self.create_dirs = create_dirs
        super(FileWriter, self).__init__()

    @asyncio.coroutine
    def read(self, count=-1):
        if self.handle is None and not self._eof:
            if self.create_dirs and not os.path.exists(os.path.dirname(self.filename)):
                os.makedirs(os.path.dirname(self.filename))
            self.handle = yield from aiofiles.open(self.filename, 'wb')
        contents = yield from self.input.read(count)
        yield from self.handle.write(contents)
        return contents

    @asyncio.coroutine
    def close(self):
        if self.input:
            yield from self.input.close()
        if self.handle:
            yield from self.handle.close()
