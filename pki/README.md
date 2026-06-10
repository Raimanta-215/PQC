# PKI certifcate authority 

## Pre-required

Create PKI root key and certificate

```bash
openssl req -x509 -new -newkey p384_mldsa65 \
-keyout pqc_ca.key -out pqc_ca.crt \
-nodes -days 3650 \
-subj "/C=FR/O=Mon Entreprise PoC/CN=PQC Root CA" \
```
Pyhton venv
```bash
python -m venv .pqc
source .pqc/bin/activate
```
## Launch server
`pyhton3 ca.py`
