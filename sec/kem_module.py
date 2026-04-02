import oqs 

class KEMModule:
    def __init__(self, alg_name):
        self.alg_name = alg_name
        self.kem = oqs.KeyEncapsulation(alg_name) 
        ## with oqs.KeyEncapsulation(alg) as kem:  losing key 
    def generate_keypair(self):
        public_key = self.kem.generate_keypair()
        secret_key = self.kem.export_secret_key()
        return public_key, secret_key
    def encapsulate(self, public_key):
        ciphertext, shared_secret = self.kem.encap_secret(public_key)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext):
        shared_secret = self.kem.decap_secret(ciphertext)
        return shared_secret
    
    def clean(self):
        self.kem.free()