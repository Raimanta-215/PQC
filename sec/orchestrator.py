import logging
from sec import KEMModule, SymmetricModule, derive_symmetric_key



log = logging.getLogger(__name__)

class PQCProtocol:
    def __init__(self, kem_alg, socket_layer):
        self.net = socket_layer
        self.kem_module = KEMModule(kem_alg)
        self.symmetric_module = None

        log.info(f"PQC Protocol initialized with KEM algorithm: {kem_alg}")

    def server_handshake(self):
        log.info("Starting server handshake...")
        # Step 1: Generate KEM key pair
        public_key, secret_key = self.kem_module.generate_keypair()
        
        # Step 2: Send public key to client
        self.net.send(public_key)
        log.info("Public key sent to client")

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
        # Step 1: Receive public key from server
        public_key = self.net.recieve()
        log.info("Public key received from server")

        if not public_key:
            log.error("Failed to receive public key from server")
            raise RuntimeError("Failed to receive public key from server")
        else:
            log.info(f"Received public key from server: {len(public_key)} bytes")
            # Step 2: Encapsulate to get ciphertext and shared secret
            ciphertext, shared_secret = self.kem_module.encapsulate(public_key)
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