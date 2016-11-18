from pkg_resources import get_distribution, DistributionNotFound

__project__ = 'syncrypt'
__version__ = '0.3.6'

try:
    __version__ = get_distribution(__project__).version
except DistributionNotFound:
    VERSION = __project__ + '-' + '(local)'
else:
    VERSION = __project__ + '-' + __version__
