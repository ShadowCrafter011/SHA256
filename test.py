from secrets import token_bytes
from bitstring import BitArray
from random import randint
from sha256 import sha256
import hashlib

def test_sha256():
    for _ in range(256):
        msg = token_bytes(randint(0, int(1e3)))
        assert hashlib.sha256(msg).digest() == sha256(msg)
