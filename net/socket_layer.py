import socket
import struct
import logging

log = logging.getLogger(__name__)

class Socket:
    def __init__(self, sock=None):
        # if sock then for client A
        # if not sock then creating a new for server B
        if sock is None:
            self.sock = socket.socket(
                            socket.AF_INET, socket.SOCK_STREAM)
            log.debug("New socket created")
        else:
            self.sock = sock
            log.debug("Socket initialized with existing socket")

    def connect(self, host, port):  
        log.info(f"Connecting to {host}:{port}...")
        try:
            #used by client alice
            self.sock.connect((host, port))
            log.info(f"Successfully connected to {host}:{port}")
        except Exception as e:
            log.error(f"Failed to connect to {host}:{port} - {str(e)}")
            raise

    def send(self, msg_byte):
        msg_len = len(msg_byte) # size of the message 
        header = struct.pack('>I', msg_len) #
        #'>' = big-endian (network byte order) - use this for all network protocols
        # I  = unsigned int   (4 bytes)
        log.debug(f"Sending message of length {msg_len} bytes. Header {header.hex()}")
        self.sock.sendall(header + msg_byte) 
        # connot mix bytes with int 


    def _recv_size_msg(self, n): # amount of octets
        chunks = [] # chunk = morceu
        bytes_recv = 0 # bytes medatory for socket comm
        while bytes_recv < n :
            try:
                chunk = self.sock.recv(min(n - bytes_recv, 4096))
                # recv(buffer) → the minimum between what is received and default size
                # manage default size not to waste RAM space
                if chunk == b'' : # b'' → bytes(msg) b'' → empty no co
                    log.warning("Socket connection broken while receiving data")
                    raise RuntimeError("socket connexion broken")
                chunks.append(chunk)
                bytes_recv += len(chunk)
            except Exception as e:
                log.error(f"Error while receiving data: {str(e)}")
                raise

        return b''.join(chunks)
    
    def recieve(self):
        try:
            header_data = self._recv_size_msg(4) # read 4 first octets
            if not header_data:
                return None
            
            msg_len, = struct.unpack('>I', header_data)
            log.debug(f"Received header: {header_data.hex()} indicating message length: {msg_len} bytes")
            
            # warning tuple return 
            payload = self._recv_size_msg(msg_len)
            log.debug(f"Received payload of length {len(payload)} bytes")
            return payload
        except Exception as e:
            log.error(f"Error while receiving message: {str(e)}")
            raise
        
    def close(self):
        self.sock.close()
        log.info("Socket closed")