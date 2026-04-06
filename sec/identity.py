from sec import SigModule

PATH_TO_CERTS = "certs/"
SK_NAME = "secret_dil_key.bin"
PK_NAME = "public_dil_key.bin"


sig = SigModule('Dilithium2')
sig.generate_keypair(PATH_TO_CERTS + PK_NAME, PATH_TO_CERTS + SK_NAME)
