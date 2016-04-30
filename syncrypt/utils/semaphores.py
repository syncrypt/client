import asyncio

class JoinableSemaphore():
    def __init__(self, maxsize=0):
        self.count = 0
        self.limiter = asyncio.Semaphore(maxsize)
        self.empty = asyncio.Lock()

    @asyncio.coroutine
    def acquire(self):
        if self.count == 0: yield from self.empty
        self.count += 1
        yield from self.limiter.acquire()

    @asyncio.coroutine
    def release(self):
        self.count -= 1
        if self.count == 0: self.empty.release()
        self.limiter.release()

    @asyncio.coroutine
    def join(self):
        yield from self.empty
        if self.empty.locked(): self.empty.release()


class JoinableSetSemaphore(JoinableSemaphore):
    def __init__(self, maxsize=0):
        self.count = 0
        self.limiter = asyncio.Semaphore(maxsize)
        self.empty = asyncio.Lock()
        self._objects = set()

    @property
    def objects(self):
        return self._objects

    @asyncio.coroutine
    def acquire(self, obj):
        if self.count == 0: yield from self.empty
        self.count += 1
        yield from self.limiter.acquire()
        self._objects.add(obj)

    @asyncio.coroutine
    def release(self, obj):
        self.count -= 1
        if self.count == 0: self.empty.release()
        self.limiter.release()
        self._objects.remove(obj)

    @asyncio.coroutine
    def join(self):
        yield from self.empty
        if self.empty.locked(): self.empty.release()
