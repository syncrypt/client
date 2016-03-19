
"""BERT-RPC Library"""

from .codec import BERTDecoder, BERTEncoder
from erlastic import Atom

encode = BERTEncoder().encode
decode = BERTDecoder().decode
