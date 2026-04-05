import socket
from net import Socket
from sec import KEMModule 
from logger import setup_logger, safe_key_hash
import logging



setup_logger('Bob')
log=logging.getLogger(__name__)



#KEM
kem = KEMModule('Kyber512')
pk, sk = kem.generate_keypair()

# network configuration
server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.bind(('192.168.174.181', 65432))
server_sock.listen()

log.info("Bob is waiting for ALICE")
client_sock, addr = server_sock.accept()
bob_sock = Socket(sock=client_sock)

try:
    log.info(f"Sending pk  {safe_key_hash(pk)}")
    bob_sock.send(pk) # send public key to alice

    log.info("Waiting for ciphertext from Alice")
    ct = bob_sock.recieve() # receive ciphertext from alice
    if not ct:
        log.error(f"Failed to receive ciphertext from Alice")
    else:
        log.info(f"Received ciphertext from Alice: {len(ct)} bytes. Decapsulating...")
        ss = kem.decapsulate(ct) # decapsulate to get shared secret
        log.info(f"Shared secret derived: {safe_key_hash(ss)}")

    log .info("Waiting for message from Alice")    
    msg = bob_sock.recieve()
    if msg:
        log.info(f"Received message from Alice: {len(msg)} bytes")
        print(f"MSG : \n {msg.decode('utf-8')}")

        ack = b'Salut Alice'
        bob_sock.send(ack)
        log.info("Sent ACK to Alice")

except Exception as e:
    log.error(f"An error occurred: {str(e)}")

finally:
    kem.clean()
    bob_sock.close()
    server_sock.close()
    log.info("Ressources cleaned up, Bob is shutting down.")