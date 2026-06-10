# Testing 

## 1. Stress-test

First, move the python script `stress_test.py` to the root file PQC/ and use parameters to launch the test.
```bash
cd PQC/
pyhton3 stress_test.py --server (on server machine)
then
python3 stress_test.py --client -ip <server_IP> -c <amount of handshake simultaneously> 
```


## Pre-required on RED for MITM and replay tests
Requires a third machine on the same network as Alice and Bob.

```bash
python3-pip 
python3-scapy 
python3-netfilterqueue 
dsniff
```
### Launch MITM and replay tests
`python3 mitm.py`
`python3 replay.py`
