from queue import Queue
import logging

log = logging.getLogger(__name__)



class MessageQueueManager:
    def __init__(self):
        self.incoming_queue = Queue()
        self.outgoing_queue = Queue()

    def put_incoming_message(self, message):
        self.incoming_queue.put(message)
        log.debug(f"Put incoming message: {len(message)} bytes")

    def get_incoming_message(self):
        message = self.incoming_queue.get()
        log.debug(f"Got incoming message: {len(message)} bytes")
        return message

    def put_outgoing_message(self, message):
        self.outgoing_queue.put(message)
        log.debug(f"Put outgoing message: {len(message)} bytes")

    def get_outgoing_message(self):
        message = self.outgoing_queue.get()
        log.debug(f"Got outgoing message: {len(message)} bytes")
        return message