from socket_layer import Socket

# init a comm
alice_socket = Socket()
alice_socket.connect('192.168.174.181', 65432) #bob
alice_socket.send(b'Hey Bob')

reply = alice_socket.recieve()
if reply:
    print(f"MSG: \n {reply.decode("utf-8")}")

alice_socket.close()