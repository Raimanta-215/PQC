import socket
from app import Socket
from sec import KEMModule 


#KEM
kem = KEMModule('Kyber512')
pk, sk = kem.generate_keypair()

# network configuration
server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.bind(('192.168.174.181', 65432))
server_sock.listen()

print("BOB is waiting for Alice")
client_sock, addr = server_sock.accept()
bob_sock = Socket(sock=client_sock)

try:

    bob_sock.send(pk) # send public key to alice

    ct = bob_sock.recieve() # receive ciphertext from alice
    
    ss = kem.decapsulate(ct) # decapsulate to get shared secret

    msg = bob_sock.recieve()
    if msg:
        print(f"MSG : \n {msg.decode('utf-8')}")
        ack = b'Salut Alice'
        bob_sock.send(ack)

finally:
    kem.clean()
    bob_sock.close()
    server_sock.close()