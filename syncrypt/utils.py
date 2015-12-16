import asyncio
import sys

@asyncio.coroutine
def stdio(loop):
    reader = asyncio.StreamReader(loop=loop)
    reader_protocol = asyncio.StreamReaderProtocol(reader)
    try:
        yield from loop.connect_read_pipe(lambda: reader_protocol, sys.stdin)
    except ValueError as e:
        raise e from None # hide exception stack
    return reader

@asyncio.coroutine
def readline_from_stdin(password=False):
    loop = asyncio.get_event_loop()
    reader = yield from stdio(loop)
    line = yield from reader.readline()
    return line.decode().replace('\r', '').replace('\n', '')
