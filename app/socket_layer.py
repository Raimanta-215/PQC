import socket
import struct

class Socket:
    def __init__(self, sock=None):
        # if sock then for client A
        # if not sock then creating a new for server B
        if sock is None:
            self.sock = socket.socket(
                            socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = sock

    def connect(self, host, port):  
        #used by client alice
        self.sock.connect((host, port))

    def send(self, msg_byte):
        msg_len = len(msg_byte) # size of the message 
        header = struct.pack('>I', msg_len) #
        #'>' = big-endian (network byte order) - use this for all network protocols
        # I  = unsigned int   (4 bytes)
        self.sock.sendall(header + msg_byte) 
        # connot mix bytes with int 


    def _recv_size_msg(self, n): # amount of octets
        chunks = [] # chunk = morceu
        bytes_recv = 0 # bytes medatory for socket comm
        while bytes_recv < n :
            chunk = self.sock.recv(min(n - bytes_recv, 4096))
            # recv(buffer) → the minimum between what is received and default size
            # manage default size not to waste RAM space
            if chunk == b'' : # b'' → bytes(msg) b'' → empty no co
                raise RuntimeError("socket connexion broken")
            chunks.append(chunk)
            bytes_recv += len(chunk)

        return b''.join(chunks)
    
    def recieve(self):
        header_data = self._recv_size_msg(4) # read 4 first octets
        if not header_data:
            return None
        msg_len, = struct.unpack('>I', header_data)
        # warning tuple return 
        return self._recv_size_msg(msg_len)
    
    def close(self):
        self.sock.close()