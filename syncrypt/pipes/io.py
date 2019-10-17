import logging
import os.path
import shutil
import sys
from typing import Optional

import trio

from .base import Pipe, Sink, Source

logger = logging.getLogger(__name__)


class StreamReader(Source):
    def __init__(self, reader: Pipe):
        super(StreamReader, self).__init__()
        self.input = reader

    async def close(self):
        # Do NOT close handle
        pass


class FileReader(Source):
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.handle = None # type: Optional[trio.abc.AsyncResource]
        super(FileReader, self).__init__()

    async def read(self, count=-1):
        if self.handle is None and not self._eof:
            self.handle = await trio.open_file(self.filename, 'rb')
        return (await self.handle.read(count))

    async def close(self):
        if self.handle:
            await self.handle.aclose()


class TrioStreamReader(Source):
    def __init__(self, stream: trio.abc.ReceiveStream) -> None:
        self.stream = stream
        super(TrioStreamReader, self).__init__()

    async def read(self, count=-1):
        return (await self.stream.receive_some(count))

    async def close(self):
        if self.stream:
            await self.stream.aclose()


class StreamWriter(Sink):
    def __init__(self, writer):
        self.writer = writer
        self.bytes_written = 0
        super(StreamWriter, self).__init__()

    async def read(self, count=-1):
        buf = await self.input.read(count)
        if buf and len(buf) > 0:
            self.writer.write(buf)
            await self.writer.drain()
            self.bytes_written += len(buf)
        return buf


class TrioStreamWriter(StreamWriter):
    async def read(self, count=-1):
        buf = await self.input.read(count)
        if buf and len(buf) > 0:
            await self.writer.send_all(buf)
            self.bytes_written += len(buf)
        return buf


class StdoutWriter(StreamWriter):
    def __init__(self):
        self.handle = sys.stdout
        super(StdoutWriter, self).__init__(self.handle.buffer)


class FileWriter(Sink):
    def __init__(self, filename, create_dirs=False, create_backup=False, store_temporary=False):
        self.filename = filename
        self.handle = None
        self.create_dirs = create_dirs
        self.create_backup = create_backup
        self.store_temporary = store_temporary
        super(FileWriter, self).__init__()

    async def read(self, count=-1):
        if self.handle is None and not self._eof:
            fn = self.filename
            if self.create_dirs and not os.path.exists(os.path.dirname(fn)):
                os.makedirs(os.path.dirname(fn))
            if self.create_backup and os.path.exists(fn) and not self.store_temporary:
                shutil.move(fn, self.get_backup_filename(fn))
            if self.store_temporary:
                fn = self.get_temporary_filename(fn)
            logger.debug('Writing to %s', fn)
            self.handle = await trio.open_file(fn, 'wb')
        contents = await self.input.read(count)
        await self.handle.write(contents)
        return contents

    async def finalize(self):
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

    async def close(self):
        if self.input:
            await self.input.close()
        if self.handle:
            await self.handle.flush()
            await self.handle.aclose()
