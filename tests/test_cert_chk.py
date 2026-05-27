import socket
import logging
from net import Socket
from logger import setup_logger
from sec import PQCProtocol
from session import SessionModule
import subprocess
import os

log = logging.getLogger(__name__)

def run_server_console():
    setup_logger('Bob')
    log = logging.getLogger(__name__)

    # KEM & Algorithmes
    ALG_KYBER = 'Kyber512'
    ALG_DIL = "ML-DSA-44"

    HOST = "0.0.0.0"  
    PORT = 65432

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen()

    log.info(f"Bob is listening on port {PORT} waiting for ALICE...")
    client_sock, addr = server_sock.accept()
    
    bob_sock = Socket(sock=client_sock)
    log.info(f"Connection established with ALICE at {addr}")
    
    protocol = PQCProtocol(ALG_KYBER, ALG_DIL, bob_sock)
    session = None  

    try:
        protocol.sign_module.load_keypair("cert/bob.pub", "cert/bob.key")
        protocol.sign_module.load_certificate("cert/bob_autosigned.crt")

        protocol.server_handshake()

        session = SessionModule(protocol)
        session.start_session()

        while session._running:
            msg = input("Enter message or 'exit' to quit..\n")
            if msg.strip().lower() == 'exit':
                break
            if msg:
                session.sending(msg.encode('utf-8'))

    except Exception as e:
        log.error(f"An error occurred: {str(e)}")

    finally:
        if session:
            session.close()
        else:
            protocol.close()

        server_sock.close()
        log.info("Resources cleaned up, Bob is shutting down.")

if __name__ == "__main__":


    command = [
                "openssl", "x509", "-req",
                "-key", "bob.key",
                "-out", "bob_autosigned.crt",
                "-days", "365",
                "-subj", "/CN=Auto_Bob"

            ]
    if not os.path.exists("bob_autosigned.crt"):
        print("Generating self-signed certificate for Bob...")
        subprocess.run(command, check=True, capture_output=True, text=True)

    run_server_console()
