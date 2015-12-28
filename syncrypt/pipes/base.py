import asyncio

#
#
#   FileReaderPipe(bundle)
#   >> DeflatingPipe('snappy')
#   >> PaddingPipe(16)
#   >> EncryptingPipe(bundle)
#   >> BufferingPipe(buf_size)
#
#

class Pipe(object):
    def __init__(self):
        self._eof = False

    @asyncio.coroutine
    def read(self, count=-1):
        pass

    def add_input(self, input):
        self.input = input

    def __rshift__(self, other):
        other.add_input(self)
        return other

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
    def __init__(self, buf_size):
        self.buf_size = buf_size
        self.buf = b''
        super(Buffered, self).__init__()

    @asyncio.coroutine
    def read(self, count=-1):
        assert count == -1 or count == self.buf_size
        while len(self.buf) < self.buf_size:
            # fill up buffer
            add_buf = yield from self.input.read(max(self.buf_size, count))
            if len(add_buf) == 0:
                self._eof = True
                break
            self.buf += add_buf
        retbuf = self.buf[:self.buf_size]
        self.buf = self.buf[self.buf_size:]
        return retbuf
