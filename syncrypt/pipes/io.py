import logging
import sys
import os.path
import shutil

import aiofiles
import asyncio

from .base import Pipe, Sink, Source

logger = logging.getLogger(__name__)

class StreamReader(Source):
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

class StreamWriter(Sink):
    def __init__(self, writer):
        self.writer = writer
        self.bytes_written = 0
        super(StreamWriter, self).__init__()

    @asyncio.coroutine
    def read(self, count=-1):
        buf = yield from self.input.read(count)
        if buf and len(buf) > 0:
            self.writer.write(buf)
            yield from self.writer.drain()
            self.bytes_written += len(buf)
        return buf

class StdoutWriter(StreamWriter):
    def __init__(self):
        self.handle = sys.stdout
        super(StdoutWriter, self).__init__(self.handle.buffer)

class FileWriter(Sink):
    # simple wrapper for aiofiles
    def __init__(self, filename, create_dirs=False, create_backup=False, store_temporary=False):
        self.filename = filename
        self.handle = None
        self.create_dirs = create_dirs
        self.create_backup = create_backup
        self.store_temporary = store_temporary
        super(FileWriter, self).__init__()

    @asyncio.coroutine
    def read(self, count=-1):
        if self.handle is None and not self._eof:
            fn = self.filename
            if self.create_dirs and not os.path.exists(os.path.dirname(fn)):
                os.makedirs(os.path.dirname(fn))
            if self.create_backup and os.path.exists(fn) and not self.store_temporary:
                shutil.move(fn, self.get_backup_filename(fn))
            if self.store_temporary:
                fn = self.get_temporary_filename(fn)
            logger.debug('Writing to %s', fn)
            self.handle = yield from aiofiles.open(fn, 'wb')
        contents = yield from self.input.read(count)
        yield from self.handle.write(contents)
        return contents

    @asyncio.coroutine
    def finalize(self):
        fn = self.filename
        if self.store_temporary: # we only wrote a temporary filename 
            if os.path.exists(fn):
                if self.create_backup:
                    shutil.move(fn, self.get_backup_filename(fn))
                else:
                    os.remove(fn)
            shutil.move(self.get_temporary_filename(fn), fn)

    def get_temporary_filename(self, filename):
        # TODO: more elaborate temporary filename composition required
        return filename + '.sctemp000'

    def get_backup_filename(self, filename):
        # TODO: more elaborate backup filename composition required
        return filename + '.scbackup'

    @asyncio.coroutine
    def close(self):
        if self.input:
            yield from self.input.close()
        if self.handle:
            yield from self.handle.close()
