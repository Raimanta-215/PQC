import socket
import struct
import logging

log = logging.getLogger(__name__)

class Socket:
    """
    Class representing a TCP socket for network communication
    including message framing with a 4-byte header indicating message length.

    Attributes:
    - sock (socket.socket), optional:
        The underlying socket object used for communication.
    
    Methods:
    - connect(host, port): 
        Establishes a connection to the specified host and port.
    - send(msg_byte): 
        Sends a message over the socket with proper framing.
    - recieve(): 
        Receives a message from the socket, handling the framing to determine message length.µ
    -_recv_size_msg(n):
        Helper method to receive a specific number of bytes from the socket, used for reading message headers
    -close():
        Closes the socket connection.
    """
    def __init__(self, sock=None):
        # if not sock then creating a new for client A
        # Bob already has a socket from accept() so we use it
        if sock is None:
            self.sock = socket.socket(
                            socket.AF_INET, socket.SOCK_STREAM)
            log.debug("New socket created")
        else:
            self.sock = sock
            log.debug("Socket initialized with existing socket")

    def connect(self, host, port):  
        """
        Establishes a connection to the specified host and port.

        Args:
        - host (str): The hostname or IP address to connect to.
        - port (int): The port number to connect to.

        Raises:
        - Exception: 
            If the connection fails, an exception is raised with details of the failure.
        """
        log.info(f"Connecting to {host}:{port}...")
        try:
            #used by client alice
            self.sock.connect((host, port))
            log.info(f"Successfully connected to {host}:{port}")
        except Exception as e:
            log.error(f"Failed to connect to {host}:{port} - {str(e)}")
            raise

    def send(self, msg_byte):
        """
        Sends a message over the socket with proper framing.

        Args:
        - msg_byte (bytes): The message to be sent, in bytes.
        
        """
        msg_len = len(msg_byte) # size of the message 
        header = struct.pack('>I', msg_len) #
        #'>' = big-endian (network byte order) - use this for all network protocols
        # I  = unsigned int   (4 bytes)
        log.debug(f"Sending message of length {msg_len} bytes. Header {header.hex()}")
        self.sock.sendall(header + msg_byte) 
        # connot mix bytes with int 


    def _recv_size_msg(self, n): # amount of octets
        """
        Helper method to receive a specific number of bytes from the socket.

        Args:
        - n (int): The number of bytes to receive.

        Returns:
        - bytes: The received data of the specified length.
        
        Raises:
        - RuntimeError: If the socket connection is broken during reception.
        - Exception: If any other error occurs during reception, an exception is raised with details of the failure.
        
        """
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
        """
        Receives a message from the socket, handling the framing to determine message length.

        returns:
        - bytes: The received message, or None if no message is received 
        """
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
        """
         Closes the socket connection.
        """
        self.sock.close()
        log.info("Socket closed")