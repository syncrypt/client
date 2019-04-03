import logging
import os

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
        super(MemoryChannelEventHandler, self).__init__()

    def dispatch(self, event):
        '''
        This function will be call in the context of the watchdog worker
        thread. We need to use a BlockingTrioPortal to communicate with
        our trio program.
        '''
        self.portal.run(self.handle_event, event)

    async def handle_event(self, event):
        '''
        This function will be run in the trio context.
        '''
        await self.channel.send(event)


class Watchdog(object):

    def __init__(self, path='.', recursive=True, event_handler=None):
        self._observer = Observer()
        evh = event_handler
        self._observer.schedule(evh, path, recursive)

    def start(self):
        self._observer.start()

    def stop(self):
        self._observer.stop()
        self._observer.join()
