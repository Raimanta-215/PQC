import logging
from sec import KEMModule, SymmetricModule, SignModule
from sec.derive import derive_keys, finish_handshake_transcript, generate_finished_mac, verify_finished_mac



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
        self.finish_transcript = b""
        log.info(f"PQC Protocol initialized with KEM algorithm: {kem_alg} and {sign_alg}")


    def server_handshake(self):
        """
        Performs the server-side handshake to establish a shared session key with the client.

        Steps:
        1. Receive the client's public key.
        2. Encapsulate a shared secret using the client's public key to obtain a ciphertext and the shared secret.
        3. Sign the ciphertext with the server's signing key.
        4. Send the client's public key, the signature, and the server's certificate to the client.
        5. Derive a symmetric session key from the shared secret and initialize the symmetric module for encryption/decryption.

        """
        log.info("Starting server handshake...")
        

        # 1. Receive public key from client
        client_kyber_public_key = self.net.receive()  # Bob receives the public key from Alice
        self.finish_transcript = client_kyber_public_key
        if not client_kyber_public_key:
            log.error("Failed to receive public key from client")
            raise RuntimeError("Failed to receive public key from client")
        

        # 2. Encapsulate to get ciphertext and shared secret
        ciphertext, shared_secret = self.kem_module.encapsulate(client_kyber_public_key)
        log.info("Encapsulation successful, preparing to send public key and signature to client")

        # 3. Sign the ciphertext with Bob's signing key
        try:
            signature = self.sign_module.sign(ciphertext)
            log.info(f"Ciphertext signed successfully. Signature length: {len(signature)} bytes")
        except Exception as e:
            log.error(f"Failed to sign the ciphertext - {str(e)}")
            raise RuntimeError("Failed to sign the ciphertext")    

        payload = [ciphertext, signature, self.sign_module.cert_data]

        # 3 : Send public key and signature to client
        for item in payload:
            self.net.send(item)
            self.finish_transcript += item
        log.info("Public key and signature sent to client")


        # 4: Derive symmetric key and initialize symmetric module
        finished_key, session_key = derive_keys(shared_secret)
        self.symmetric_module = SymmetricModule(session_key)
        log.info("Symmetric module initialized with derived session key")

        transcript_hash = finish_handshake_transcript(self.finish_transcript)
        finished_mac = generate_finished_mac(finished_key, transcript_hash)

        
        self.send_encrypted_msg(finished_mac)

        

    def client_handshake(self):
        """
        Performs the client-side handshake to establish a shared session key with the server.

        Steps:
        1. Generate an ephemeral key pair and send the public key to the server.
        2. Receive the ciphertext, signature, and server's certificate from the server.
        3. Verify the server's certificate and the signature of the received public key.
        4. Decapsulate the received ciphertext using the ephemeral secret key to obtain the shared secret.
        5. Derive a symmetric session key from the shared secret and initialize the symmetric module
        """
        log.info("Starting client handshake...")
        #  1: CLIENT HELLO create a key pair and send the public key to the server

        ephemeral_public_key, ephemeral_secret_key = self.kem_module.generate_key_pair()
        self.net.send(ephemeral_public_key)
        self.finish_transcript = ephemeral_public_key
        log.info("CLIENT HELLO - Client public key sent to server")        

        ciphertext = self.net.receive()
        self.finish_transcript += ciphertext
        signature  = self.net.receive()
        self.finish_transcript += signature
        bob_crt    = self.net.receive()
        self.finish_transcript += bob_crt

        
        log.info("Datas received from server")

        ## VERIFICATION OF THE RECEIVED DATA
        expected_lengths = {
            "ciphertext" : self.kem_module.kem.details['length_ciphertext'],
            "signature" : self.sign_module.signer.details['length_signature']
        }


        if len(ciphertext) != expected_lengths["ciphertext"]:
            log.error(f"Received ciphertext length {len(ciphertext)} does not match expected length {expected_lengths['ciphertext']}")
            raise ValueError("Invalid ciphertext length received from server")
        if len(signature) != expected_lengths["signature"]:
            log.error(f"Received signature length {len(signature)} does not match expected length {expected_lengths['signature']}")
            raise ValueError("Invalid signature length received from server")
        if len(bob_crt) == 0:
            log.error("Received empty certificate from server")
            raise ValueError("Empty certificate received from server")
        
        log.info(f"Received ciphertext from server: {len(ciphertext)} bytes, signature length: {len(signature)} bytes, certificate length: {len(bob_crt)} bytes")

        ca_path = "cert/pqc_ca.crt"

        # 2 : verify identity of the received public key
        bob_pub_key = self.sign_module.verify_with_pki(bob_crt, ca_path)
        if not bob_pub_key:
            log.error("Invalid signature for the received public key")
            raise PermissionError("Invalid signature for the received public key")
        log.info("Signature of the received public key is valid")
        
        # Verify Bob signature
        is_valid_signature = self.sign_module.verify_signature(ciphertext, signature, bob_pub_key)
        if not is_valid_signature:
            log.error("Invalid signature for the received public key")
            raise PermissionError("Invalid signature for the received public key")
        log.info("Signature of the received public key is valid")


        #  3: Encapsulate to get ciphertext and shared secret
        shared_secret = self.kem_module.decapsulate(ciphertext, ephemeral_secret_key)
        log.info("Encapsulation successful, sending ciphertext to server")

        #  4: Derive symmetric key and initialize symmetric module
        finished_key, session_key = derive_keys(shared_secret)
        self.symmetric_module = SymmetricModule(session_key)
        log.info("Symmetric module initialized with derived session key")

        transcript_hash = finish_handshake_transcript(self.finish_transcript)
        finished_mac = generate_finished_mac(finished_key, transcript_hash)

        server_finished = self.receive_encrypted_msg()
        if not verify_finished_mac(finished_key, transcript_hash, server_finished):
            log.error("Handshake verification failed: Server's finished message does not match expected value")
            raise RuntimeError("Handshake verification failed")

        self.send_encrypted_msg(finished_mac)



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