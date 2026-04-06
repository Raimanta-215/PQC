import logging
import os 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from logger import safe_key_hash

log = logging.getLogger(__name__)

class SymmetricModule:
    def __init__(self, key):
        self.key = key
        self.aesgcm = AESGCM(self.key)
        log.info(f"SymmetricModule initialized with key: {safe_key_hash(self.key)}")

    def encrypt(self, plaintext):
        iv_dyn = os.urandom(12)  # Generate a random IV for each encryption
        log.info(f"Encrypting data with IV: {safe_key_hash(iv_dyn)}")
        
        ciphertext = self.aesgcm.encrypt(iv_dyn, plaintext, None)
        log.info(f"Data encrypted (ciphertext length: {len(ciphertext)} bytes)")
        return iv_dyn + ciphertext  # Prepend IV to the ciphertext for later use in decryption

    def decrypt(self, ciphertext):
        iv_rcv = ciphertext[:12]  # Extract the IV from the beginning of the ciphertext
        encrypted_data = ciphertext[12:]  # Extract the actual encrypted data
        try:
            plaintext = self.aesgcm.decrypt(iv_rcv, encrypted_data, None)
            log.info(f"Data decrypted successfully (plaintext length: {len(plaintext)} bytes)")
            return plaintext
        except InvalidTag:
            log.error("Decryption failed: Invalid authentication tag")
            return None