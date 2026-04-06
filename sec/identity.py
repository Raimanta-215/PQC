from sec import SignModule
import logging

log = logging.getLogger(__name__)

PATH_TO_CERTS = "certs/"
SK_NAME = "secret_dil_key.bin"
PK_NAME = "public_dil_key.bin"


def create_dilithium_key():
    log.info("Starting certificate generation for SERVER..")

    sig = SignModule('Dilithium2')
    sig.generate_keypair(PATH_TO_CERTS + PK_NAME, PATH_TO_CERTS + SK_NAME)


