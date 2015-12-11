import logging
import unittest

from test_binary import *
from test_local import *

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

if __name__ == '__main__':
    unittest.main()
