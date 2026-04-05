import oqs 
import logging
from logger_pqc import safe_key_hash

log = logging.getLogger(__name__)

class KEMModule:
    def __init__(self, alg_name):
        self.alg_name = alg_name
        self.kem = oqs.KeyEncapsulation(alg_name) 
        ## with oqs.KeyEncapsulation(alg) as kem:  losing key 
        log.info(f"KEM Module initialized with algorithm: {alg_name}")
   
    def generate_keypair(self):
        public_key = self.kem.generate_keypair()
        secret_key = self.kem.export_secret_key()

        log.info(f"Key pair generated: {safe_key_hash(public_key)} length: {len(public_key)} bytes")

        return public_key, secret_key


    def encapsulate(self, public_key):
        log.info(f"Encapsulating with public key: {safe_key_hash(public_key)}")
        try:
            ciphertext, shared_secret = self.kem.encap_secret(public_key)

            log.info(f"Encapsulation successful: Ciphertext {safe_key_hash(ciphertext)} length: {len(ciphertext)} bytes, Shared secret {safe_key_hash(shared_secret)}")
            return ciphertext, shared_secret

        except Exception as e:
            log.error(f"Error occurred during encapsulation: {str(e)}")
            raise
    def decapsulate(self, ciphertext):
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