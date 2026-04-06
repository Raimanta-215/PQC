from net import Socket
from sec import KEMModule
import logging
from logger import safe_key_hash, setup_logger
from sec import PQCProtocol

setup_logger('Alice')
log = logging.getLogger(__name__)

#KEM
ALG_KYBER = 'Kyber512'

# init a comm
alice_socket = Socket()
alice_socket.connect('192.168.174.181', 65432) #bob

protocol = PQCProtocol(ALG_KYBER, alice_socket)
try:

    protocol.client_handshake() 

    log.info("Sending message to Bob")
    protocol.send_encrypted_msg(b'Hey Bob')

    reply = protocol.receive_encrypted_msg()
    if reply:
        log.info(f"Received reply from Bob: {len(reply)} bytes")
        print(f"MSG: \n {reply.decode("utf-8")}")

except Exception as e:
    log.error(f"An error occurred: {str(e)}")

finally:
    protocol.close()
    log.info("Connection closed, Alice is shutting down.")