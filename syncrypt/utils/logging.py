import logging.config
import sys
import colorlog

if sys.platform == 'win32':
    class SafeColoredFormatter(colorlog.ColoredFormatter):
        # On windows, we will encode the string with 'replace' (converts unknown character
        # codes to '?'), so that we will have no problem logging in to a limit charmap
        # terminal :(
        def format(self, record):
            formatted = super(SafeColoredFormatter, self).format(record)
            return formatted.encode('cp1252', 'replace').decode('cp1252')

    ColoredFormatter = SafeColoredFormatter
else:
    ColoredFormatter = colorlog.ColoredFormatter


def setup_logging(loglevel, logfile=None):
    config = {
        'version': 1,
        'formatters': {
            'colored': {
                '()': ColoredFormatter,
                'format': '%(log_color)s%(asctime)s [%(levelname).1s] %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S',
                'log_colors': {
                    'DEBUG':    'cyan',
                    'INFO':     'white',
                    'WARNING':  'yellow',
                    'ERROR':    'red',
                    'CRITICAL': 'red,bg_white',
                    }
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
            'asyncio': {
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
