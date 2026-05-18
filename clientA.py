from net import Socket
from sec import KEMModule
import logging
from logger import safe_key_hash, setup_logger
from sec import PQCProtocol
import requests
from session import SessionModule
from session.session import SessionModule

setup_logger('Alice')
log = logging.getLogger(__name__)

'''
def update_ca_trust(pki_url, save_path="certs/pqc_ca.crt"):
    try:
        response = requests.get(f"{pki_url}/ca")
        if response.status_code == 200:
            ca_content = response.json()["certificate"]
            with open(save_path, "w") as f:
                f.write(ca_content)
            print(f"Confiance établie : {save_path} mis à jour.")
            return True
    except Exception as e:
        print(f"Erreur lors de la récupération du CA : {e}")
        return False

#curl -s http://192.168.174.192:5000/ca | jq -r '.certificate' > certs/pqc_ca.crt

update_ca_trust("http://192.168.174.192:5000")

'''
#KEM
ALG_KYBER = 'Kyber512'
ALG_DIL = "ML-DSA-44"

HOST_BOB = "192.168.174.181"
PORT_BOB = 65432

# init a comm
alice_socket = Socket()
alice_socket.connect(HOST_BOB, PORT_BOB) #bob

protocol = PQCProtocol(ALG_KYBER, ALG_DIL, alice_socket)

try:

    protocol.client_handshake() 

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
    if 'session' in locals():  ## Check if session was created before trying to close it
        session.close()
    else: ## If session was not created, ensure protocol is closed to free resources
        protocol.close()

    log.info("Connection closed, Alice is shutting down.")