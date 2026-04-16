import logging 
from logger import safe_key_hash
import oqs 
import os

log = logging.getLogger(__name__)

class SignModule:
    """
    A module for handling PQC signature operations.


    """
    def __init__(self, alg_name):
        self.alg_name = alg_name
        self.signer = oqs.Signature(alg_name)
        self.secret_dil_key = None
        log.info(f"Signature Module initialized with algorithm: {alg_name}")




    def generate_keypair(self, pk_file_path, sk_file_path):
        public_key = self.signer.generate_keypair()
        secret_key = self.signer.export_secret_key()

        try:
            if not os.path.exists(pk_file_path):
                with open(pk_file_path, 'wb') as pk_file:
                    pk_file.write(public_key)
                log.info(f"Public key saved to {pk_file_path}")

            if not os.path.exists(sk_file_path):
                with open(sk_file_path, 'wb') as sk_file:
                    sk_file.write(secret_key)
                log.info(f"Secret key saved to {sk_file_path}")
        except Exception as e:
            log.error(f"Error occurred while saving keys: {str(e)}")
            raise

        log.info(f"Key pair generated: {safe_key_hash(public_key)} length: {len(public_key)} bytes")

    def load_keypair(self, pk_file_path="certs/public_dil_key.bin", sk_file_path="certs/secret_dil_key.bin"):
        try:
            with open(pk_file_path, 'rb') as pk_file:
                public_key = pk_file.read()
            log.info(f"Public key loaded from {pk_file_path}")

            with open(sk_file_path, 'rb') as sk_file:
                secret_key = sk_file.read()
            log.info(f"Secret key loaded from {sk_file_path}")

            self.secret_dil_key = secret_key
            return public_key, secret_key
        except Exception as e:
            log.error(f"Error occurred while loading keys: {str(e)}")
            raise
    def sign(self, message):
        log.info(f"Signing message of length: {len(message)} bytes")
        try:
            if self.secret_dil_key is None:
                raise ValueError("Secret key is not loaded")
            
            log.info(f"Message signed successfully: Signature {safe_key_hash(signature)} length: {len(signature)} bytes")
            return self.signer.sign(message, self.secret_dil_key)
        except Exception as e:
            log.error(f"Error occurred during signing: {str(e)}")
            raise

    def verify(self, message, signature, public_key):
        log.info(f"Verifying signature for message of length: {len(message)} bytes with public key: {safe_key_hash(public_key)}")
        try:
            result = self.signer.verify(message, signature, public_key)
            if result:
                log.info("Signature verification successful")
            else:
                log.warning("Signature verification failed")
            return result
        except Exception as e:
            log.error(f"Error occurred during verification: {str(e)}")
            raise

    def clean(self):
        self.signer.free()
        log.info("Signature resources cleaned up.")