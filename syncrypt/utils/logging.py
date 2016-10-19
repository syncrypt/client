import logging.config
import colorlog

def setup_logging(loglevel, logfile=None):
    config = {
        'version': 1,
        'formatters': {
            'colored': {
                '()': colorlog.ColoredFormatter,
                'format':
                    '%(log_color)s[%(levelname)-8s] %(message)s',
            },
            'precise': {
                'format': '%(asctime)s %(levelname)s [%(name)s] %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S'
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
            'aiohttp': {
                'handlers': ['stream'],
                'level': loglevel
            },
        },
    }
    if logfile:
        config['handlers']['file'] = {
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'level': logging.DEBUG,
            'filename': logfile,
            'when': 'D',
            'formatter': 'precise',
            'backupCount': 30
        }
        config['loggers']['syncrypt']['handlers'].append('file')
        config['loggers']['syncrypt']['level'] = logging.DEBUG
        config['loggers']['aiohttp']['handlers'].append('file')
        config['loggers']['aiohttp']['level'] = logging.DEBUG
    logging.config.dictConfig(config)
