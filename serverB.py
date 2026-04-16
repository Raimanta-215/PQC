import socket
from net import Socket
from sec import KEMModule 
from logger import setup_logger, safe_key_hash
import logging
from sec import PQCProtocol



setup_logger('Bob')
log=logging.getLogger(__name__)



#KEM
ALG_KYBER = 'Kyber512'

# network configuration
server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.bind(('192.168.174.181', 65432))
server_sock.listen()

log.info("Bob is waiting for ALICE")
client_sock, addr = server_sock.accept()
bob_sock = Socket(sock=client_sock) # Wrap the accepted socket in our Socket class for communication
log.info(f"Connection established with ALICE at {addr}")
protocol = PQCProtocol(ALG_KYBER, bob_sock)

try:
    protocol.server_handshake()

    msg = protocol.receive_encrypted_msg()
    if msg:
        log.info(f"Received message from Alice: {len(msg)} bytes")
        print(f"MSG : \n {msg.decode('utf-8')}")

        protocol.send_encrypted_msg(b'ACK')
        log.info("Sent ACK to Alice")

except Exception as e:
    log.error(f"An error occurred: {str(e)}")

finally:
    protocol.close()
    server_sock.close()
    log.info("Ressources cleaned up, Bob is shutting down.")