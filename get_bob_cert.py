import json
import requests

with open("cert/bob.csr", "r") as f:
    csr_text = f.read()

payload = {
    "identity": "Bob",
    "csr": csr_text
}

response = requests.post("http://192.168.174.183:5000/ca/certificate", json=payload)

if response.status_code == 200:
    cert_text = response.json()['certificate']

    with open("cert/bob.crt", "w") as f:
        f.write(cert_text)
    print("Certificate X.509 bob.crt !")
else:
    print("Error:", response.text)

'''
openssl genpkey -algorithm p384_mldsa65 -provider oqsprovider -provider default -out cert/bob.key

openssl req -new -key cert/bob.key -subj "/CN=Bob" -provider oqsprovider -provider default -out cert/bob.csr
'''