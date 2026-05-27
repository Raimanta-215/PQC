import logging 
from logger import safe_key_hash
import oqs 
import subprocess
import os
import tempfile

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
        
        msg_fd,  msg_path = tempfile.mkstemp(suffix=".bin", prefix="pqc_msg_")
        sig_fd,  sig_path = tempfile.mkstemp(suffix=".bin", prefix="pqc_sig_")

        os.close(msg_fd)
        os.close(sig_fd)
        try:
            with open(msg_path, "wb") as f: f.write(message)

            # Commande native (sans provider args)
            subprocess.run([
                "openssl", "pkeyutl", "-sign",
                "-inkey", self.secret_dil_key_path,
                "-in", msg_path,
                "-out", sig_path
            ], check=True, capture_output=True)

            with open(sig_path, "rb") as f:
                signature = f.read()
            return signature
        finally:
            for path in (msg_path, sig_path):
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
    def verify_with_pki(self, peer_cert_bytes, ca_cert_path):

        cert_fd,  cert_path   = tempfile.mkstemp(suffix=".crt", prefix="pqc_cert_")
        pubk_fd,  pubk_path   = tempfile.mkstemp(suffix=".pem", prefix="pqc_pub_")

        try:
            os.close(cert_fd)
            os.close(pubk_fd)

            with open(cert_path, "wb") as f: f.write(peer_cert_bytes)

            result = subprocess.run([
                "openssl", "verify", "-CAfile", ca_cert_path, cert_path
            ], capture_output=True, text=True)

            if result.returncode != 0:
                log.error(f"PKI Verification failed: {result.stderr}")
                return None

            with open(pubk_path, "w") as f_out:
                subprocess.run([
                    "openssl", "x509", "-in", cert_path, "-pubkey", "-noout"
                ], stdout=f_out, check=True)

            return pubk_path
        except Exception as e:
            log.error(f"Error during PKI validation: {e}")
            return None


    def verify_signature(self, message, signature, pub_key_path):
        """Vérifie la signature mathématique avec la clé publique extraite du certificat."""
        msg_fd,  msg_path = tempfile.mkstemp(suffix=".bin", prefix="pqc_vmsg_")
        sig_fd,  sig_path = tempfile.mkstemp(suffix=".bin", prefix="pqc_vsig_")

        try:

            os.close(msg_fd)
            os.close(sig_fd)
            
            with open(msg_path, "wb") as f: f.write(message)
            with open(sig_path, "wb") as f: f.write(signature)

            result = subprocess.run([
                "openssl", "pkeyutl", "-verify",
                "-pubin", "-inkey", pub_key_path,
                "-sigfile", sig_path,
                "-in", msg_path
            ], capture_output=True, text=True)

            if "Signature Verified Successfully" in result.stdout:
                return True
            else:
                log.error(f"Signature verification failed: {result.stderr}")
                return False
        finally:
            for path in (msg_path, sig_path):
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
    def clean(self):
            """Clean up local references."""
            self.pk_path = None
            self.sk_path = None
            log.info("Signature module state cleared.")

            #OpenSSL does not require explicit cleanup of keys, 
            # but we can remove any temporary files if needed.