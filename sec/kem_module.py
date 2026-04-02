import oqs 

class KEMModule:
    def __init__(self, alg_name):
        self.alg_name = alg_name
        #self.kem = oqs.KeyEncapsulation(alg_name) ## or with oqs.KeyEncapsulation(alg) as kem: ?

    def generate_keypair(self):
        with oqs.KeyEncapsulation(self.alg_name) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
        return public_key, secret_key
    def encapsulate(self, public_key):
        with oqs.KeyEncapsulation(self.alg_name) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext, secret_key):
        with oqs.KeyEncapsulation(self.alg_name) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        return shared_secret