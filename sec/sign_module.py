import logging 
from logger import safe_key_hash
import oqs 
import subprocess
import os

log = logging.getLogger(__name__)

class SignModule:
    """
    A module for handling PQC signature operations.


    """
    def __init__(self, alg_name):
        self.alg_name = alg_name
        self.signer = oqs.Signature(alg_name)

        self.secret_dil_key_path = None
        self.public_dil_key_path = None
        self.cert_path = None

        self.cert_data = None
        log.info(f"Signature Module initialized with algorithm: {alg_name}")




    def generate_keypair(self, pk_file_path, sk_file_path):

        try :
            subprocess.run([
                "openssl", "genpkey",
                "-algorithm", self.alg_name, 
                "-out", sk_file_path], check=True)

            subprocess.run([
                "openssl", "pkey",
                "-in", sk_file_path,
                "-pubout",
                "-out", pk_file_path], check=True)
            
            self.public_dil_key_path = pk_file_path
            self.secret_dil_key_path = sk_file_path

            log.info(f"Key pair generated and saved: Public key at {pk_file_path}, Secret key at {sk_file_path}" )
        except subprocess.CalledProcessError as e:
            log.error(f"Error occurred during key generation: {str(e)}")
            raise


    def load_certificate(self, cert_path):
        """Charge le certificat de Bob et ses octets pour le réseau."""
        try:
            if os.path.exists(cert_path):
                self.cert_path = cert_path
                with open(cert_path, "rb") as cert_file:
                    self.cert_data = cert_file.read()
                log.info(f"Certificate loaded successfully from {cert_path}")
                return True
            else:
                log.error(f"Certificate file not found: {cert_path}")
                return False
        except Exception as e:
            log.error(f"Error loading certificate: {str(e)}")
            raise

    def load_keypair(self, pk_file_path, sk_file_path):
        """Charge les chemins des clés de Bob."""
        if os.path.exists(pk_file_path) and os.path.exists(sk_file_path):
            self.public_dil_key_path = pk_file_path
            self.secret_dil_key_path = sk_file_path
            log.info("Key pair paths loaded successfully.")
            return True
        return False
    def sign(self, message):
        """Signe un message (ex: la clé publique KEM) avec la clé privée de Bob."""
        if not self.secret_dil_key_path:
            raise RuntimeError("Secret key path not loaded.")
        
        msg_temp = "temp_message.bin"
        sig_temp = "temp_signature.bin"

        try:
            with open(msg_temp, "wb") as f: f.write(message)

            # Commande native (sans provider args)
            subprocess.run([
                "openssl", "pkeyutl", "-sign",
                "-inkey", self.secret_dil_key_path,
                "-in", msg_temp,
                "-out", sig_temp
            ], check=True, capture_output=True)

            with open(sig_temp, "rb") as f:
                signature = f.read()
            return signature
        finally:
            for f in [msg_temp, sig_temp]:
                if os.path.exists(f): os.remove(f)

    def verify_with_pki(self, peer_cert_bytes, ca_cert_path):

        temp_cert = "temp_bob_received.crt"
        temp_pub_key = "temp_bob_pub_extracted.pem"

        try:
            with open(temp_cert, "wb") as f: f.write(peer_cert_bytes)

            result = subprocess.run([
                "openssl", "verify", "-CAfile", ca_cert_path, temp_cert
            ], capture_output=True, text=True)

            if result.returncode != 0:
                log.error(f"PKI Verification failed: {result.stderr}")
                return None

            with open(temp_pub_key, "w") as f_out:
                subprocess.run([
                    "openssl", "x509", "-in", temp_cert, "-pubkey", "-noout"
                ], stdout=f_out, check=True)

            return temp_pub_key
        except Exception as e:
            log.error(f"Error during PKI validation: {e}")
            return None


    def verify_signature(self, message, signature, pub_key_path):
        """Vérifie la signature mathématique avec la clé publique extraite du certificat."""
        msg_temp = "temp_msg_verify.bin"
        sig_temp = "temp_sig_verify.bin"
        
        try:
            with open(msg_temp, "wb") as f: f.write(message)
            with open(sig_temp, "wb") as f: f.write(signature)

            result = subprocess.run([
                "openssl", "pkeyutl", "-verify",
                "-pubin", "-inkey", pub_key_path,
                "-sigfile", sig_temp,
                "-in", msg_temp
            ], capture_output=True, text=True)

            if "Signature Verified Successfully" in result.stdout:
                return True
            else:
                log.error(f"Signature verification failed: {result.stderr}")
                return False
        finally:
            for f in [msg_temp, sig_temp]:
                if os.path.exists(f): os.remove(f)
    def clean(self):
            """Clean up local references."""
            self.pk_path = None
            self.sk_path = None
            log.info("Signature module state cleared.")

            #OpenSSL does not require explicit cleanup of keys, 
            # but we can remove any temporary files if needed.