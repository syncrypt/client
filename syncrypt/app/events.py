import logging
import os
import threading

import trio.abc
from watchdog.observers import Observer

logger = logging.getLogger(__name__)


class MemoryChannelEventHandler:
    '''
    A watchdog wrapper that will report file changes back to the syncrypt
    controller app.
    '''

    def __init__(self, channel: trio.abc.SendChannel):
        self.channel = channel
        self.portal = trio.BlockingTrioPortal()
        self.lock = threading.Lock()
        super(MemoryChannelEventHandler, self).__init__()

    def dispatch(self, event):
        '''
        This function will be call in the context of the watchdog worker
        thread. We need to use a BlockingTrioPortal to communicate with
        our trio program.
        '''
        with self.lock:
            try:
                self.portal.run(self.handle_event, event)
            except (trio.RunFinishedError, trio.Cancelled):
                pass
            except Exception as e:
                logger.exception('Unknown exception during portal.run')

    async def handle_event(self, event):
        '''
        This function will be run in the trio context.
        '''
        await self.channel.send(event)


class Watchdog(object):

    def __init__(self, path='.', recursive=True, event_handler=None):
        self._observer = Observer()
        self.event_handler = event_handler
        self._observer.schedule(self.event_handler, path, recursive)

    def start(self):
        self._observer.start()

    async def stop(self):
        while self.event_handler.lock.locked():
            await trio.sleep(1)
        with self.event_handler.lock:
            self._observer.stop()
            self._observer.join()
