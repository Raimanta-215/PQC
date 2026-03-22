import socket
from socket_layer import Socket


server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.bind(('192.168.174.181', 65432))
server_sock.listen()

print("BOB is waiting for Alice")
client_sock, addr = server_sock.accept()

bob_sock = Socket(sock=client_sock)
try:

    msg = bob_sock.recieve()
    if msg:
        print(f"MSG : \n {msg.decode('utf-8')}")
        ack = b'Salut Alice'
        bob_sock.send(ack)

finally:
    bob_sock.close()
    server_sock.close()