from net import Socket
from sec import KEMModule
import logging
from logger import safe_key_hash, setup_logger

setup_logger('Alice')
log = logging.getLogger(__name__)

#KEM
kem = KEMModule('Kyber512')

# init a comm
alice_socket = Socket()
alice_socket.connect('192.168.174.181', 65432) #bob


try:
    log.info("Connected to Bob, waiting for public key...")
    pk_bob = alice_socket.recieve() # receive public key from bob

    if not pk_bob:
        log.error("Failed to receive public key from Bob")
    else:
        log.info(f"Received public key from Bob: {safe_key_hash(pk_bob)} length: {len(pk_bob)} bytes")
        
        log.info("Encapsulating secret with Bob's public key...")
        ct, ss = kem.encapsulate(pk_bob) # encapsulate to get ciphertext and shared secret

        log.info(f"Ciphertext generated: {safe_key_hash(ct)} length: {len(ct)} bytes")

        alice_socket.send(ct) # send ciphertext to bob
        log.info("Ciphertext sent to Bob")

        log.info("Sending message to Bob")
        alice_socket.send(b'Hey Bob')

        reply = alice_socket.recieve()
        if reply:
            log.info(f"Received reply from Bob: {len(reply)} bytes")
            print(f"MSG: \n {reply.decode("utf-8")}")

except Exception as e:
    log.error(f"An error occurred: {str(e)}")

finally:
    alice_socket.close()
    log.info("Connection closed, Alice is shutting down.")