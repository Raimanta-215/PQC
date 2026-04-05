import logging
import hashlib


def setup_logger(role=None):
    logging.basicConfig(
        level=logging.INFO,
        format=f'%(asctime)s - [{role}] - %(name)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )


def safe_key_hash(key):
    if not key:
        return None
    return hashlib.sha256(key).hexdigest()[:8]