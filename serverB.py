import socket
from net import Socket
from sec import KEMModule 
from logger import setup_logger, safe_key_hash
import logging
from sec import PQCProtocol
from session import SessionModule



setup_logger('Bob')
log=logging.getLogger(__name__)



#KEM
ALG_KYBER = 'Kyber512'
ALG_DIL = "ML-DSA-44"


# network configuration

HOST_BOB = "192.168.174.181"
PORT = 65432

server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.bind((HOST_BOB, PORT))
server_sock.listen()

log.info("Bob is waiting for ALICE")
client_sock, addr = server_sock.accept()
bob_sock = Socket(sock=client_sock) # Wrap the accepted socket in our Socket class for communication
log.info(f"Connection established with ALICE at {addr}")
protocol = PQCProtocol(ALG_KYBER, ALG_DIL, bob_sock)

try:
#####openssl pkey -in cert/bob.key -pubout -out cert/bob.pub


    protocol.sign_module.load_keypair("cert/bob.pub", "cert/bob.key")
    protocol.sign_module.load_certificate("cert/bob.crt")

    protocol.server_handshake()

    session = SessionModule(protocol)
    session.start_session()

    while session._running:
        msg = input("Enter message or 'exit' to quit..\n")
        if msg == 'exit':
            break
        session.sending(msg.encode('utf-8'))
        


except Exception as e:
    log.error(f"An error occurred: {str(e)}")

finally:
    if 'session' in locals():
        session.close()
    else:
        protocol.close()

    server_sock.close()
    log.info("Ressources cleaned up, Bob is shutting down.")

