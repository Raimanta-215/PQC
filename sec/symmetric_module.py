import logging
import os 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from logger import safe_key_hash

log = logging.getLogger(__name__)

class SymmetricModule:

    """
    A module for handling symmetric encryption and decryption using AES-GCM.
    This module provides functionalities to encrypt and decrypt messages using a symmetric key derived from a shared secret. It utilizes AES-GCM for authenticated encryption, ensuring both confidentiality and integrity of the data.

    Attributes:
    - key (bytes): The symmetric key used for encryption and decryption.
    - aesgcm (AESGCM): An instance of the AESGCM class initialized
        with the provided symmetric key.

    Methods:
    - encrypt(plaintext): Encrypts the given plaintext using AES-GCM and returns the ciphertext
    - decrypt(ciphertext): Decrypts the given ciphertext using AES-GCM and returns the plaintext. If decryption fails due to an invalid authentication tag, it returns None.

    """
    def __init__(self, key):
        self.key = key
        self.aesgcm = AESGCM(self.key)
        log.info(f"SymmetricModule initialized with key: {safe_key_hash(self.key)}")

    def encrypt(self, plaintext):
        """
        Encrypts the given plaintext using AES-GCM and returns the ciphertext.

        Args:
        - plaintext (bytes): The plaintext message to be encrypted.
        returns:
        - bytes: The resulting ciphertext, which includes the IV prepended to the actual encrypted data
        """
        iv_dyn = os.urandom(12)  # Generate a random IV for each encryption
        log.info(f"Encrypting data with IV: {safe_key_hash(iv_dyn)}")
        
        ciphertext = self.aesgcm.encrypt(iv_dyn, plaintext, None)
        log.info(f"Data encrypted (ciphertext length: {len(ciphertext)} bytes)")
        return iv_dyn + ciphertext  # Prepend IV to the ciphertext for later use in decryption

    def decrypt(self, ciphertext):

        """
        Decrypts the given ciphertext using AES-GCM and returns the plaintext. If decryption fails due to an invalid authentication tag, it returns None.

        Args:
        - ciphertext (bytes): The ciphertext to be decrypted, which should include the IV prepended
        to the actual encrypted data.
        returns:
        - bytes: The decrypted plaintext message, or None if decryption fails due to an invalid
        """
        iv_rcv = ciphertext[:12]  # Extract the IV from the beginning of the ciphertext
        encrypted_data = ciphertext[12:]  # Extract the actual encrypted data
        try:
            plaintext = self.aesgcm.decrypt(iv_rcv, encrypted_data, None)
            log.info(f"Data decrypted successfully (plaintext length: {len(plaintext)} bytes)")
            return plaintext
        except InvalidTag:
            log.error("Decryption failed: Invalid authentication tag")
            return None