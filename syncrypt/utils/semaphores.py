import asyncio
from typing import Generic, TypeVar, Set

T = TypeVar('T')


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


class JoinableSetSemaphore(JoinableSemaphore, Generic[T]):
    def __init__(self, maxsize=0):
        self.count = 0
        self.limiter = asyncio.Semaphore(maxsize)
        self.empty = asyncio.Lock()
        self._objects = set() # type: Set[T]

    @property
    def objects(self) -> Set[T]:
        return self._objects

    async def acquire(self, obj: T): # type: ignore
        if self.count == 0: await self.empty
        self.count += 1
        await self.limiter.acquire()
        self._objects.add(obj)

    async def release(self, obj: T): # type: ignore
        self.count -= 1
        if self.count == 0: self.empty.release()
        self.limiter.release()
        self._objects.remove(obj)

    async def join(self):
        await self.empty
        if self.empty.locked(): self.empty.release()
