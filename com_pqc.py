import argparse
import socket
import logging
import threading
from typing import Optional
from net import Socket
from logger import setup_logger, safe_key_hash
from sec import PQCProtocol
from session import SessionModule
from tui import UserInterface

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
    session = None  # Initialisation propre pour le bloc finally

    try:
        protocol.sign_module.load_keypair("cert/bob.pub", "cert/bob.key")
        protocol.sign_module.load_certificate("cert/bob.crt")

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
def run_client_console(target_ip):
    setup_logger('Alice')
    log = logging.getLogger(__name__)

    # KEM & Algorithmes
    ALG_KYBER = 'Kyber512'
    ALG_DIL = "ML-DSA-44"

    PORT_BOB = 65432

    # Initialisation de la communication
    alice_socket = Socket()
    
    try:
        log.info(f"Connecting to Bob at {target_ip}:{PORT_BOB}...")
        alice_socket.connect(target_ip, PORT_BOB)
    except Exception as e:
        log.error(f"Failed to connect to {target_ip}: {e}")
        return

    protocol = PQCProtocol(ALG_KYBER, ALG_DIL, alice_socket)
    session = None

    try:
        protocol.client_handshake() 

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

        log.info("Connection closed, Alice is shutting down.")

def run_server():
    log.info("Starting server with TUI interface...")
    app = UserInterface(role="server", target_ip="")
    app.run()
def run_client(target_ip):
    log.info("Starting client with TUI interface...")
    app = UserInterface(role="client", target_ip=target_ip)
    app.run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PQC Chat Application")
    group = parser.add_mutually_exclusive_group(required=True)
    
    group.add_argument("--server", action="store_true", help="Run in server mode (Bob)")
    group.add_argument("--client", action="store_true", help="Run in client mode (Alice)")
    
    # Argument pour l'IP cible
    parser.add_argument("--ip", type=str, default="192.168.174.181", help="Target IP for client")
    
    # Argument pour l'interface
    parser.add_argument(
        "-I", "--interface",
        action="store_true",
        help="Use TUI interface (Textual) instead of console"
    )
    
    args = parser.parse_args()

    if args.server:
        if args.interface:
            run_server()
        else:
            run_server_console()
    elif args.client:
        if args.interface:
            run_client(args.ip)
        else:
            run_client_console(args.ip)