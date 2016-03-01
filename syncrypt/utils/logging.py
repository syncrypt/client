import logging.config
import colorlog

def setup_logging(loglevel):
    logging.config.dictConfig({
        'version': 1,
        'formatters': {
            'colored': {
                '()': colorlog.ColoredFormatter,
                'format':
                    '%(log_color)s%(levelname)s:%(name)s:%(message)s',
            }
        },
        'handlers': {
            'stream': {
                'class': 'logging.StreamHandler',
                'formatter': 'colored',
                'level': loglevel
            },
        },
        'loggers': {
            'syncrypt': {
                'handlers': ['stream'],
                'level': loglevel
            },
        },
    })
