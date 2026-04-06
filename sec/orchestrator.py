import logging
from sec import KEMModule, SymmetricModule, derive_symmetric_key, SignModule



log = logging.getLogger(__name__)

class PQCProtocol:
    def __init__(self, kem_alg, sign_alg, socket_layer):
        self.net = socket_layer
        self.kem_module = KEMModule(kem_alg)
        self.symmetric_module = None
        self.sign_module = SignModule(sign_alg)  
        log.info(f"PQC Protocol initialized with KEM algorithm: {kem_alg} and {sign_alg}")

    def server_handshake(self):
        log.info("Starting server handshake...")
        # Step 1: Generate KEM key pair
        public_key, secret_key = self.kem_module.generate_keypair()
        
        # Step 2: Send public key to client with signature
        sign = self.sign_module.sign(public_key)

        payload = (public_key, sign)
        self.net.send(payload)
        log.info("Public key and signature sent to client")

        # Step 3: Receive encapsulated key from client
        ciphertext = self.net.recieve()
        log.info("Encapsulated key received from client")

        # Step 4: Decapsulate to get shared secret
        if not ciphertext:
            log.error("Failed to receive encapsulated key from client")
            raise RuntimeError("Failed to receive encapsulated key from client")
        else:
            shared_secret = self.kem_module.decapsulate(ciphertext)
            log.info("Shared secret decapsulated successfully")

        # Step 5: Derive symmetric key and initialize symmetric module
            session_key = derive_symmetric_key(shared_secret)
            self.symmetric_module = SymmetricModule(session_key)
            log.info("Symmetric module initialized with derived session key")

    def client_handshake(self):
        log.info("Starting client handshake...")
        # Step 1: Receive data (public key and signature) from server
        data = self.net.recieve()
        log.info("Data received from server")

        size_private_key = self.kem_module.kem.details['public_key_length'] + self.sign_module.signer.details['signature_length']
        extracted_private_key = data[:size_private_key]
        signature = data[size_private_key:]

        if not data:
            log.error("Failed to receive data from server")
            raise RuntimeError("Failed to receive data from server")
        else:
            if not self.sign_module.verify(extracted_private_key, signature, extracted_private_key):
                log.error("Signature verification failed for received public key")
                raise RuntimeError("Signature verification failed for received public key")
            
            log.info(f"Received public key from server: {size_private_key} bytes")
            # Step 2: Encapsulate to get ciphertext and shared secret
            ciphertext, shared_secret = self.kem_module.encapsulate(extracted_private_key)
            log.info("Encapsulation successful, sending ciphertext to server")

            # Step 3: Send encapsulated key to server
            self.net.send(ciphertext)
            log.info("Ciphertext sent to server")

            # Step 4: Derive symmetric key and initialize symmetric module
            session_key = derive_symmetric_key(shared_secret)
            self.symmetric_module = SymmetricModule(session_key)
            log.info("Symmetric module initialized with derived session key")


    def send_encrypted_msg(self, msg):
        if self.symmetric_module is None:
            log.error("Symmetric module not initialized. Cannot send encrypted message.")
            raise RuntimeError("Symmetric module not initialized")

        ciphertext = self.symmetric_module.encrypt(msg)
        self.net.send(ciphertext)
        log.info(f"Encrypted message sent (ciphertext length: {len(ciphertext)} bytes)")

    def receive_encrypted_msg(self):
        if self.symmetric_module is None:
            log.error("Symmetric module not initialized. Cannot receive encrypted message.")
            raise RuntimeError("Symmetric module not initialized")

        ciphertext = self.net.recieve()
        log.info(f"Encrypted message received (ciphertext length: {len(ciphertext)} bytes)")
        plaintext = self.symmetric_module.decrypt(ciphertext)
        if plaintext is not None:
            log.info(f"Encrypted message decrypted successfully (plaintext length: {len(plaintext)} bytes)")
        else:
            log.warning("Failed to decrypt the received message")
        return plaintext
    
    def close(self):
        log.info("Closing PQC Protocol resources...")
            
        self.net.close()
        log.info("PQC Protocol resources closed successfully")