import threading
import logging
from net import MessageQueueManager, ProtocolHandler

log = logging.getLogger(__name__)


class SessionModule:

    def __init__(self, protocol):
        self.protocol = protocol
        self.queue = MessageQueueManager()
        self.handler = ProtocolHandler(protocol, self.queue)
        self._running = False

    def start_session(self):
        self._running = True
        log.info("Session started.")
        # Here you can add any session initialization logic if needed
        tr_rcv = threading.Thread(target=self._recv_loop, daemon=True)
        tr_rcv.start()

        tr_proc = threading.Thread(target=self._process_loop, daemon=True)
        tr_proc.start()

    def sending(self, data: bytes):
        log.info(f"Sending data: {len(data)} bytes")
        self.handler.send(data)

    def _recv_loop(self):
        while self._running:
            try:
                self.handler.receive_into_queue()

            except Exception as e:
                log.error(f"Error receiving message: {str(e)}")
                self.close()


    def _process_loop(self):
        while self._running:
            try:
                msg = self.queue.get_incoming_message()
                if msg:
                    log.info(f"Received message: {len(msg)} bytes")
                    print(f"[MSG RCV]: {msg.decode('utf-8')}")
            except Exception as e:
                log.error(f"Error processing message: {str(e)}")
                self.close()


    def close(self):
        self._running = False
        self.protocol.close()
        log.info("Session closed.")