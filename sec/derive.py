from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import logging
from logger import safe_key_hash
import hmac
import hashlib

log = logging.getLogger(__name__)

def derive_symmetric_key(shared_secret, info, length):
    """
    Derives a symmetric key from the shared secret using HKDF.

    Args:
    - shared_secret (bytes): The shared secret obtained from KEM encapsulation/decapsulation
    - info (bytes): Optional context and application specific information (default: b'key')
    - length (int): The desired length of the derived key in bytes (default: 16 for AES-128)

    returns:
    - bytes: The derived symmetric key.
    """
    hkdf_key = HKDF(
        algorithm=hashes.SHA256(),
        length=length, #36o for AES-256
        salt=None,
        info=info,
    )
    derived_key = hkdf_key.derive(shared_secret)
    log.info(f"Derived symmetric key: {safe_key_hash(derived_key)} )length: {len(derived_key)} bytes")

    return derived_key

def derive_keys(shared_secret):
    sess_key = derive_symmetric_key(shared_secret, info=b'key', length=32)
    finished_key = derive_symmetric_key(shared_secret, info=b'finished key', length=32)
    return sess_key, finished_key


def finish_handshake_transcript(transcript):
    """
    Finalizes the handshake transcript by hashing it.

    Args:
    - transcript (bytes): The complete handshake transcript.

    returns:
    - bytes: The hash of the handshake transcript.
    """
    transcript_hash = hashes.Hash(hashes.SHA256())
    transcript_hash.update(transcript)
    final_hash = transcript_hash.finalize()
    log.info(f"Finalized handshake transcript hash: {final_hash}")
    return final_hash

def generate_finished_mac(finished_key, transcript_hash):
    """
    Generates a MAC for the finished message using the finished key and transcript hash.

    Args:
    - finished_key (bytes): The derived finished key.
    - transcript_hash (bytes): The hash of the handshake transcript.

    returns:
    - bytes: The generated MAC for the finished message.
    """
    finished_mac = hmac.new(finished_key, transcript_hash, hashlib.sha256).digest()
    log.info(f"Generated finished MAC: {finished_mac}")
    return finished_mac


def verify_finished_mac(finished_key, transcript_hash, received_mac):
    """
    Verifies the received finished MAC against the expected value.

    Args:
    - finished_key (bytes): The derived finished key.
    - transcript_hash (bytes): The hash of the handshake transcript.
    - received_mac (bytes): The MAC received from the peer to verify.

    returns:
    - bool: True if the MAC is valid, False otherwise.
    """
    expected_mac = generate_finished_mac(finished_key, transcript_hash)
    is_valid = hmac.compare_digest(received_mac, expected_mac)
    if is_valid:
        log.info("Finished MAC verification successful")
    else:
        log.error("Finished MAC verification failed")
    return is_valid


