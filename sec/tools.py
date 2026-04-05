from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import logging
from logger import safe_key_hash


log = logging.getLogger(__name__)

def derive_symmetric_key(shared_secret, info=b'key', length=16):
    hkdf_key = HKDF(
        algorithm=hashes.SHA256(),
        length=length, #36o for AES-256
        salt=None,
        info=info,
    )
    aes_key = hkdf_key.derive(shared_secret)
    log.info(f"Derived symmetric key: {safe_key_hash(aes_key)} )length: {len(aes_key)} bytes")

    return aes_key