import oqs 
import logging
from logger import safe_key_hash

log = logging.getLogger(__name__)

class KEMModule:

    """
    A module for handling PQC key encapsulation mechanisms (KEM).

    This module provides functionalities to generate key pairs, encapsulate a shared secret using a public key, and decapsulate a shared secret using a ciphertext. It is designed to work with the OQS library for post-quantum cryptographic operations.

    Attributes:
    - alg_name (str): The name of the KEM algorithm being used.
    - kem (oqs.KeyEncapsulation): An instance of the OQS KeyEncapsulation class initialized with the specified algorithm.

    Methods:
    - generate_keypair(): Generates a public and secret key pair for the KEM algorithm.
    - encapsulate(public_key): Encapsulates a shared secret using the provided public key, returning the ciphertext and the shared secret.
    - decapsulate(ciphertext): Decapsulates the provided ciphertext to retrieve the shared secret
    - clean(): Frees the resources associated with the KEM instance.

    """
    def __init__(self, alg_name):
        self.alg_name = alg_name
        self.kem = oqs.KeyEncapsulation(alg_name) 
        ## with oqs.KeyEncapsulation(alg) as kem:  losing key 
        log.info(f"KEM Module initialized with algorithm: {alg_name}")
   
    def generate_keypair(self):
        """
        Generates a public and secret key pair for the KEM algorithm.
        returns:
        - tuple: A tuple containing the public key and secret key.
        """
        public_key = self.kem.generate_keypair()
        secret_key = self.kem.export_secret_key()

        log.info(f"Key pair generated: {safe_key_hash(public_key)} length: {len(public_key)} bytes")

        return public_key, secret_key


    def encapsulate(self, public_key):
        """
        Encapsulates a shared secret using the provided public key.
        Args:
        - public_key (bytes): The public key to use for encapsulation.

        returns:
        - tuple: A tuple containing the ciphertext and the shared secret.
        """
        log.info(f"Encapsulating with public key: {safe_key_hash(public_key)}")
        try:
            ciphertext, shared_secret = self.kem.encap_secret(public_key)

            log.info(f"Encapsulation successful: Ciphertext {safe_key_hash(ciphertext)} length: {len(ciphertext)} bytes, Shared secret {safe_key_hash(shared_secret)}")
            return ciphertext, shared_secret

        except Exception as e:
            log.error(f"Error occurred during encapsulation: {str(e)}")
            raise
    def decapsulate(self, ciphertext):
        """
        Decapsulates the provided ciphertext to retrieve the shared secret.

        Args:
        - ciphertext (bytes): The ciphertext to decapsulate.
        returns:
        - bytes: The shared secret obtained from decapsulation.
        Raises:
        - Exception: If an error occurs during decapsulation, an exception is raised with details of the failure.
        """
        log.info(f"Decapsulating ciphertext: {safe_key_hash(ciphertext)}")
        try:
            shared_secret = self.kem.decap_secret(ciphertext)
            log.info(f"Decapsulation successful: Shared secret {safe_key_hash(shared_secret)}")
            return shared_secret
        except Exception as e:
            log.error(f"Error occurred during decapsulation: {str(e)}")
            raise

    def clean(self):
        self.kem.free()
        log.info("KEM resources cleaned up.")