import asyncio

import logging
from syncrypt.utils.semaphores import JoinableSemaphore

logger = logging.getLogger(__name__)


class AsyncContext:

    def __init__(self, semaphore=None, concurrency=8):
        self.loop = asyncio.get_event_loop()
        self.semaphore = semaphore or JoinableSemaphore(concurrency)
        self.running_tasks = {}
        self.failed_tasks = {}

    def __enter__(self):
        return self

    def __exit__(self, ex_type, ex_val, tb):
        # assert semaphore = 0
        pass
        #print(self, ex_type, ex_val)

    @asyncio.coroutine
    def wait(self):
        if self.semaphore:
            yield from self.semaphore.join()
        if self.failed_tasks:
            raise Exception("{0} task(s) failed!".format(len(self.failed_tasks.items())))

    @asyncio.coroutine
    def create_task(self, task_key, coro):
        if self.semaphore:
            yield from self.semaphore.acquire()

        task = self.loop.create_task(coro)

        def done_cb(_task):
            try:
                if task_key in self.running_tasks:
                    del self.running_tasks[task_key]

                if _task.cancelled():
                    logger.info("Upload of %s got canceled.", task_key)

                if _task.exception():
                    ex = _task.exception()
                    #print("EX")
                    logger.error("Exception in task %s (%s)", task, task_key)
                    #import ipdb; ipdb.set_trace()
                    logger.exception(ex)
                    #, stack_info=_task.get_stack())
                    self.failed_tasks[task_key] = task

                if self.semaphore:
                    self.loop.create_task(self.semaphore.release())
            except Exception as e:
                print(e)

        self.running_tasks[task_key] = task
        task.add_done_callback(done_cb)
