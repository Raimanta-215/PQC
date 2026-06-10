import logging
import hashlib


class Logger(logging.Handler):
    def __init__(self, app_instance):
        super().__init__()
        self.app = app_instance

    def emit(self, record):
        log_entry = self.format(record)
        try:
                self.app.call_from_thread(self.app.log_to_monitor, log_entry)
        except Exception as e:
            print(f"Error emitting log message: {str(e)}")
# to enable logs storage into file, remove comment lines 'filename' and 'filemode'
def setup_logger(role=None):
    logging.basicConfig(
        level=logging.INFO,
        format=f'%(asctime)s - [{role}] - %(name)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S',
        #filename=f"{role.lower()}.log" if role else 'app.log',
        #filemode='a',
        encoding='utf-8',
        force=True
    )


def safe_key_hash(key):
    if not key:
        return None
    return hashlib.sha256(key).hexdigest()[:8]
