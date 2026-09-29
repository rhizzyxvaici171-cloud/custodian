"""
Low-level hashing and signing primitives. Kept separate from the
directory-walking logic in baseline.py so each can be tested in
isolation.
"""

import hashlib
import hmac

CHUNK_SIZE = 65536


def hash_file(path):
    """SHA-256 of a file's contents, read in chunks so large files don't
    need to fit in memory at once."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sign(data_bytes, key):
    """HMAC-SHA256 of data_bytes under key, as a hex string."""
    return hmac.new(key.encode("utf-8"), data_bytes, hashlib.sha256).hexdigest()


def verify_signature(data_bytes, key, expected_signature):
    """
    Constant-time comparison, the same reasoning as this portfolio's
    Bastion project applies to password/token comparisons: a naive
    string == comparison leaks how many leading bytes matched via
    response timing, irrelevant for a purely local CLI tool's own
    process, but a bad habit to write into shared crypto-adjacent code.
    """
    actual_signature = sign(data_bytes, key)
    return hmac.compare_digest(actual_signature, expected_signature)
