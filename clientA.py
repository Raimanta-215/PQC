from net import Socket
from sec import KEMModule
import logging
from logger import safe_key_hash, setup_logger
from sec import PQCProtocol
import requests

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