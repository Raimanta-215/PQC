import logging
from sec import KEMModule, SymmetricModule, derive_symmetric_key, SignModule



log = logging.getLogger(__name__)

class PQCProtocol:
    """
    Class to handle the post-quantum cryptographic protocol 
    for secure communication between a client and a server.
    
    This protocol includes a handshake phase for key exchange and
    methods for sending and receiving encrypted messages using the established session key.

    Attributes:
    - net (Socket): The socket layer used for network communication.
    - kem_module (KEMModule): The module for key encapsulation mechanism operations.
    - symmetric_module (SymmetricModule): The module for symmetric encryption and decryption, initialized after the handshake.
    - sign_module (SignModule): The module for digital signature operations.

    Methods:
    - server_handshake(): Performs the server-side handshake to establish a shared session key with the client.
    - client_handshake(): Performs the client-side handshake to establish a shared session key with the server.
    - send_encrypted_msg(msg): Encrypts and sends a message to the other party.
    - receive_encrypted_msg(): Receives and decrypts a message from the other party.
    - close(): Closes the protocol resources, including the network connection.


    """
    def __init__(self, kem_alg, sign_alg, socket_layer):
        self.net = socket_layer
        self.kem_module = KEMModule(kem_alg)
        self.symmetric_module = None
        self.sign_module = SignModule(sign_alg)  
        log.info(f"PQC Protocol initialized with KEM algorithm: {kem_alg} and {sign_alg}")


    def server_handshake(self):
        """
        Performs the server-side handshake to establish a shared session key with the client.

        Steps:
        1. Generate a KEM key pair (public and secret keys).    
        2. Sign the public key using the signature module.
        3. Send the public key and its signature to the client.
        4. Receive the encapsulated key (ciphertext) from the client.
        5. Decapsulate the received ciphertext to obtain the shared secret.
        6. Derive a symmetric session key from the shared secret and initialize the symmetric module for encryption/decryption.


        """
        log.info("Starting server handshake...")
        # 1 : Generate KEM key pair
        public_key, secret_key = self.kem_module.generate_keypair()
        
        # 2 : Sign the Kyber public key

        try:
            signature = self.sign_module.sign(public_key)
            log.info(f"Public key signed successfully. Signature length: {len(signature)} bytes")
        except Exception as e:
            log.error(f"Error occurred during signing the public key: {str(e)}")
            raise RuntimeError("Failed to sign the public key") from e


        payload = [public_key, signature, self.sign_module.cert_data]

        # 3 : Send public key and signature to client
        for item in payload:
            self.net.send(item)
        log.info("Public key and signature sent to client")

        # 4 : Receive encapsulated key from client
        ciphertext = self.net.recieve()
        log.info("Encapsulated key received from client")

        # 5 : Decapsulate to get shared secret
        if not ciphertext:
            log.error("Failed to receive encapsulated key from client")
            raise RuntimeError("Failed to receive encapsulated key from client")
        else:
            shared_secret = self.kem_module.decapsulate(ciphertext)
            log.info("Shared secret decapsulated successfully")

        # 6: Derive symmetric key and initialize symmetric module
            session_key = derive_symmetric_key(shared_secret)
            self.symmetric_module = SymmetricModule(session_key)
            log.info("Symmetric module initialized with derived session key")

    def client_handshake(self):
        """
        Performs the client-side handshake to establish a shared session key with the server.

        Steps:
        1. Receive the server's public key and its signature.
        2. Verify the Bob signature of the received public key.
        3. Encapsulate a shared secret using the received public key to obtain a ciphertext and the shared secret.
        4. Send the encapsulated key (ciphertext) back to the server.
        5. Derive a symmetric session key from the shared secret and initialize the symmetric module  for encryption/decryption.

        """
        log.info("Starting client handshake...")
        #  1: Receive public key from server

        public_key = self.net.recieve()
        signature  = self.net.recieve()
        bob_crt    = self.net.recieve()   
        
        log.info("Datas received from server")

        ## VERIFICATION OF THE RECEIVED DATA
        expected_lengths = {
            "public_key" : self.kem_module.kem.details['length_public_key'],
            "signature" : self.sign_module.signer.details['length_signature']
        }


        if len(public_key) != expected_lengths["public_key"]:
            log.error(f"Received public key length {len(public_key)} does not match expected length {expected_lengths['public_key']}")
            raise ValueError("Invalid public key length received from server")
        if len(signature) != expected_lengths["signature"]:
            log.error(f"Received signature length {len(signature)} does not match expected length {expected_lengths['signature']}")
            raise ValueError("Invalid signature length received from server")
        if len(bob_crt) == 0:
            log.error("Received empty certificate from server")
            raise ValueError("Empty certificate received from server")
        
        log.info(f"Received public key from server: {len(public_key)} bytes, signature length: {len(signature)} bytes, certificate length: {len(bob_crt)} bytes")

        ca_path = "cert/pqc_ca.crt"

        # 2 : verify identity of the received public key
        bob_pub_key = self.sign_module.verify_with_pki(bob_crt, ca_path)
        if not bob_pub_key:
            log.error("Invalid signature for the received public key")
            raise PermissionError("Invalid signature for the received public key")
        log.info("Signature of the received public key is valid")
        
        # Verify Bob signature
        is_valid_signature = self.sign_module.verify_signature(public_key, signature, bob_pub_key)
        if not is_valid_signature:
            log.error("Invalid signature for the received public key")
            raise PermissionError("Invalid signature for the received public key")
        log.info("Signature of the received public key is valid")


        #  3: Encapsulate to get ciphertext and shared secret
        ciphertext, shared_secret = self.kem_module.encapsulate(public_key)
        log.info("Encapsulation successful, sending ciphertext to server")

        #  4: Send encapsulated key to server
        self.net.send(ciphertext)
        log.info("Ciphertext sent to server")

        #  5: Derive symmetric key and initialize symmetric module
        session_key = derive_symmetric_key(shared_secret)
        self.symmetric_module = SymmetricModule(session_key)
        log.info("Symmetric module initialized with derived session key")

    def send_encrypted_msg(self, msg):
        """
        Encrypts and sends a message to the other party.

        Args:
        - msg (bytes): The plaintext message to be encrypted and sent.

        Raises:
        - RuntimeError: If the symmetric module is not initialized, an error is raised indicating that
            the encrypted message cannot be sent.

        """
        if self.symmetric_module is None:
            log.error("Symmetric module not initialized. Cannot send encrypted message.")
            raise RuntimeError("Symmetric module not initialized")

        ciphertext = self.symmetric_module.encrypt(msg)
        self.net.send(ciphertext)
        log.info(f"Encrypted message sent (ciphertext length: {len(ciphertext)} bytes)")

    def receive_encrypted_msg(self):
        """
        Receives and decrypts a message from the other party.
        
        returns:
        - bytes: The decrypted plaintext message received from the other party.

        Raises:
        - RuntimeError: If the symmetric module is not initialized, an error is raised indicating that
        """
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