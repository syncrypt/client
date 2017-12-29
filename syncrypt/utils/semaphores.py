import asyncio

class JoinableSemaphore():
    def __init__(self, maxsize=0):
        self.count = 0
        self.limiter = asyncio.Semaphore(maxsize)
        self.empty = asyncio.Lock()

    async def acquire(self):
        if self.count == 0: await self.empty
        self.count += 1
        await self.limiter.acquire()

    async def release(self):
        self.count -= 1
        if self.count == 0: self.empty.release()
        self.limiter.release()

    async def join(self):
        await self.empty
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

    async def acquire(self, obj):
        if self.count == 0: await self.empty
        self.count += 1
        await self.limiter.acquire()
        self._objects.add(obj)

    async def release(self, obj):
        self.count -= 1
        if self.count == 0: self.empty.release()
        self.limiter.release()
        self._objects.remove(obj)

    async def join(self):
        await self.empty
        if self.empty.locked(): self.empty.release()
