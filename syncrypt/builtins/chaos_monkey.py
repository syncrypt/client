'''
This builtin module implements a basic chaos monkey. It will randomly raise an exception in
specific function calls to harden the code.
'''

import asyncio
import inspect
import logging
import random
import sys

import smokesignal

logger = logging.getLogger(__name__)

CHAOS_TABLE = [
    # Function names, Probability, Exception
    (('write_term', 'read_term'), 0.015, IOError),
    (('open_connection',), 0.1, IOError)
]

def chaos_trace(frame, event, arg):
    if event == 'call':
        try:
            tb = inspect.getframeinfo(frame)
        except AttributeError:
            return chaos_trace
        for (function_names, probability, exc) in CHAOS_TABLE:
            if tb.function in function_names:
                if random.random() < probability:
                    logger.warn('Chaos monkey triggered for %s @ %s:%s',
                                tb.function, tb.filename, tb.lineno)
                    raise exc('Chaos Monkey at it')
    return chaos_trace

async def settrace_periodically():
    '''
    Unfortunately, raising an exception in the trace function above will remove the trace handler
    for some reason. In this task, we will set our handler again so that the chaos monkey can
    continue doing his job.
    '''
    while True:
        if sys.gettrace() != chaos_trace:
            sys.settrace(chaos_trace)
        await asyncio.sleep(2)

@smokesignal.once('pre_setup')
def pre_setup(app):
    #random.seed(12345)
    sys.settrace(chaos_trace)
    loop = asyncio.get_event_loop()
    loop.create_task(settrace_periodically())

