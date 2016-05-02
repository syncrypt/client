import asyncio


class Pipe(object):
    def __init__(self):
        self._eof = False
        self.input = None

    @asyncio.coroutine
    def read(self, count=-1):
        if self.input:
            return self.input.read(count)
        else:
            raise NotImplementedError()

    @asyncio.coroutine
    def close(self):
        if self.input:
            return self.input.close()

    @asyncio.coroutine
    def consume(self):
        'read all data from this pipe, but forget about that data'
        try:
            while True:
                if len((yield from self.read())) == 0:
                    break
        finally:
            yield from self.close()

    @asyncio.coroutine
    def readall(self):
        'read all data from this pipe and return that'
        data = b''
        while True:
            new_data = yield from self.read()
            if len(new_data) == 0:
                break
            data += new_data
        yield from self.close()
        return data

    def add_input(self, input):
        self.input = input

    def __rshift__(self, other):
        other.add_input(self)
        return other

class Source(Pipe):
    pass

class Sink(Pipe):
    pass

class Once(Pipe):
    def __init__(self, contents):
        self.contents = contents
        super(Once, self).__init__()

    @asyncio.coroutine
    def read(self, count=-1):
        if not self._eof:
            self._eof = True
            return self.contents
        else:
            return b''

class Repeat(Pipe):
    def __init__(self, count=2):
        self.count = count
        self.copies = 0
        super(Repeat, self).__init__()

    @asyncio.coroutine
    def read(self, count=-1):
        if self.copies == 0:
            self.buf = yield from self.input.read()
            if len(self.buf) > 0:
                self.copies = self.count
        if self.copies > 0:
            self.copies -= 1
        return self.buf

class Buffered(Pipe):
    '''
    This pipe will chop the input stream in parts like this:

    +-------------+------------+------------+------------+----
    | {head_size} | {buf_size} | {buf_size} | {buf_size} | ...
    +-------------+------------+------------+------------+----

    '''
    def __init__(self, buf_size, head_size=0):
        self.buf_size = buf_size
        self.buf = b''
        self.head = False
        self.head_size = head_size
        super(Buffered, self).__init__()

    @asyncio.coroutine
    def read(self, count=-1):
        assert count == -1 or count == self.buf_size or \
                (not self.head and count == self.head_size)

        if not self.head and self.head_size > 0:
            assert count == self.head_size
            self.buf += yield from self.input.read(count)
            self.head = True
            return self.pop(self.head_size)

        while len(self.buf) < self.buf_size:
            # fill up buffer
            add_buf = yield from self.input.read(max(self.buf_size, count))
            if len(add_buf) == 0:
                self._eof = True
                break
            self.buf += add_buf
        return self.pop(self.buf_size)

    def pop(self, length):
        retbuf = self.buf[:length]
        self.buf = self.buf[length:]
        return retbuf

class Limit(Pipe):
    '''
    This pipe will at most read 'limit' bytes from the input pipe
    '''
    def __init__(self, limit):
        self.bytes_limit = limit
        self.bytes_read = 0
        super(Limit, self).__init__()

    @asyncio.coroutine
    def read(self, count=-1):
        # fill up buffer
        left = self.bytes_limit - self.bytes_read
        if left == 0:
            self._eof = True
            return b''
        buf = yield from self.input.read(max(count, left))
        if len(buf) == 0:
            self._eof = True
        else:
            self.bytes_read += len(buf)
        return buf

class Count(Pipe):
    def __init__(self):
        super(Count, self).__init__()
        self._bytes_passed = 0

    @property
    def count(self):
        return self._bytes_passed

    @asyncio.coroutine
    def read(self, count=-1):
        buf = yield from self.input.read(count)
        self._bytes_passed += len(buf)
        return buf
