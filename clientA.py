from app import Socket
from sec import KEMModule


#KEM
kem = KEMModule('Kyber512')

# init a comm
alice_socket = Socket()
alice_socket.connect('192.168.174.181', 65432) #bob


try:

    pk_bob = alice_socket.recieve() # receive public key from bob

    ct, ss = kem.encapsulate(pk_bob) # encapsulate to get ciphertext and shared secret

    alice_socket.send(ct) # send ciphertext to bob
    
    alice_socket.send(b'Hey Bob')

    reply = alice_socket.recieve()
    if reply:
        print(f"MSG: \n {reply.decode("utf-8")}")

finally:
    alice_socket.close()