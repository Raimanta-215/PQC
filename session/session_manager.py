from net import Socket
from sec import PQCProtocol
import logging
import socket

from session.session_module import SessionModule

log = logging.getLogger(__name__)

ALG_KYBER = 'Kyber512'
ALG_DIL = "ML-DSA-44"
class SessionManager:

    def establish_client(self, host, port):
        # 1 socket

        net = Socket()
        net.connect(host, port)

        # 2 protocol handler

        protocol = PQCProtocol(ALG_KYBER, ALG_DIL, net)
        protocol.client_handshake()
        log.info("Client handshake completed.")

        # 3 session

        self.session = SessionModule(protocol)
        self.session.start_session()
        log.info("Client session established.")


    def establish_server(self, host, port):
        # 1 socket

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(host, port)
        server_sock.listen()


        log.info("Waiting for incoming connections...")
        client_sock, addr = server_sock.accept()
        log.info(f"Connection established with {addr}")
        net = Socket(sock=client_sock)

        # 2 protocol handler

        protocol = PQCProtocol(ALG_KYBER, ALG_DIL, net)
        protocol.server_handshake()
        log.info("Server handshake completed.")

        # 3 session

        self.session = SessionModule(protocol)
        self.session.start_session()
        log.info("Server session established.")