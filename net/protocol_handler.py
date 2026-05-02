import logging

log = logging.getLogger(__name__)


class ProtocolHandler:
    def __init__(self, protocol, queue_manager):
        self.protocol = protocol
        self.queue    = queue_manager

    def send(self, data: bytes):
        self.protocol.send_encrypted_msg(data)

    def receive_into_queue(self):
        msg = self.protocol.receive_encrypted_msg()
        if msg:
            self.queue.put_incoming_message(msg)