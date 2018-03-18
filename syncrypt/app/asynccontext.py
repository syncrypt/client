import asyncio

import logging
from syncrypt.utils.semaphores import JoinableSemaphore

logger = logging.getLogger(__name__)


class AsyncContext:

    def __init__(self, semaphore=None, concurrency: int = 8) -> None:
        self.loop = asyncio.get_event_loop()
        self.semaphore = semaphore or JoinableSemaphore(concurrency)
        self.running_tasks = {}
        self.failed_tasks = {}
        self._completed_tasks = asyncio.Queue(maxsize=concurrency)

    async def __aenter__(self):
        return self

    async def __aexit__(self, ex_type, ex_val, tb):
        for task in self.running_tasks.values():
            # Wait, assert semaphore = 0, or at least warn if != 0
            task.cancel()

    def completed_tasks(self, wait=False):
        '''Will return an iterator for the currently completed tasks, if any.'''
        try:
            while True:
                yield self._completed_tasks.get_nowait()

        except asyncio.QueueEmpty:
            pass

    def raise_for_failures(self):
        for result in self.completed_tasks():
            if result.exception():
                raise result.exception()

    async def wait(self):
        if self.semaphore:
            await self.semaphore.join()

    async def create_task(self, task_key, coro):
        if self.semaphore:
            await self.semaphore.acquire()
        task = self.loop.create_task(coro)

        def done_cb(_task):
            try:
                if task_key in self.running_tasks:
                    del self.running_tasks[task_key]
                if _task.cancelled():
                    logger.info("Task %s (%s) got canceled.", task, task_key)
                if _task.exception():
                    ex = _task.exception()
                    logger.error("Exception in task %s (%s)", task, task_key)
                    logger.exception(ex)
                    self.failed_tasks[task_key] = task
                self._completed_tasks.put_nowait(task)
                if self.semaphore:
                    self.loop.create_task(self.semaphore.release())
            except Exception as e:
                print(e)

        self.running_tasks[task_key] = task
        task.add_done_callback(done_cb)
