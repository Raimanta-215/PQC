import socket
import logging
import threading
import time
import sys
import argparse
import statistics
from net import Socket
from logger import setup_logger
from sec import PQCProtocol
from session import SessionModule

log = logging.getLogger(__name__)

lock_results = threading.Lock()
results = []   # with dict : {id, succes, delay_ms, errors}


def run_client_thread(thread_id: int, target_ip: str, port: int = 65432):
    ALG_KYBER = "Kyber512"
    ALG_DIL   = "ML-DSA-44"

    debut    = time.perf_counter()
    sock_raw = None
    session  = None
    protocol = None

    try:
        sock_raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_raw.settimeout(10)
        sock_raw.connect((target_ip, port))

        alice_sock = Socket(sock=sock_raw)
        protocol   = PQCProtocol(ALG_KYBER, ALG_DIL, alice_sock)


        protocol.client_handshake()
        delay_ms = (time.perf_counter() - debut) * 1000

        session = SessionModule(protocol)
        session.start_session()
        session.close()

        with lock_results:
            results.append({
                "id":       thread_id,
                "succes":   True,
                "delay_ms": delay_ms,
                "errors":   None,
            })

    except Exception as e:
        delay_ms = (time.perf_counter() - debut) * 1000
        with lock_results:
            results.append({
                "id":       thread_id,
                "succes":   False,
                "delay_ms": delay_ms,
                "errors":   str(e),
            })
    finally:
        if session:    session.close()
        elif protocol: protocol.close()
        elif sock_raw: sock_raw.close()


def show_feedback():
    """Calculate and display the aggregated statistics of the stress test."""
    succes  = [r for r in results if r["succes"]]
    fails  = [r for r in results if not r["succes"]]
    delay  = [r["delay_ms"] for r in succes]

    print("\n" + "═" * 52)
    print("        Stress Test results")
    print("═" * 52)
    print(f"  Total connections  : {len(results)}")
    print(f"  [^^] Success          : {len(succes)}")
    print(f"  [xx] Failures          : {len(fails)}")

    if delay:
        print(f"\n  Handshake latency (ms)")
        print(f"     Min    : {min(delay):.1f} ms")
        print(f"     Max    : {max(delay):.1f} ms")
        print(f"     Moy    : {statistics.mean(delay):.1f} ms")
        # if len(delay) > 1:
        #     print(f"     Médiane: {statistics.median(delay):.1f} ms")
        #     print(f"     Écart-type: {statistics.stdev(delay):.1f} ms")

    if fails:
        print(f"\n  /1\ Errors encountered :")
        vus = set()
        for r in fails:
            msg = r["errors"]
            if msg not in vus:
                print(f"     → {msg}")
                vus.add(msg)

    print("═" * 52 + "\n")


def run_client_console(target_ip: str, nb_tests: int):
    """
    Stress test multi-threaded with metrics collection.
    :param target_ip:  Server IP to connect to (Bob)
    :param nb_tests:   Total number of connections to attempt
    """
    setup_logger("Alice-StressTest")
    print(f"\n[*] Stress Test PQC — {nb_tests} connected to {target_ip}")

    threads   = []
    debut_global = time.perf_counter()

    for i in range(1, nb_tests + 1):
        t = threading.Thread(
            target=run_client_thread,
            args=(i, target_ip),
            daemon=True,
        )
        threads.append(t)
        t.start()

        sys.stdout.write(f"\r  → Launching threads : {i}/{nb_tests}")
        sys.stdout.flush()


    print(f"\n[*] Waiting for all handshakes to complete...")

    for t in threads:
        t.join(timeout=30)

    duree_totale = (time.perf_counter() - debut_global)
    print(f"[*] Total test duration : {duree_totale:.2f} s")

    show_feedback()


def manage_client_thread(client_sock, addr):
    ALG_KYBER = "Kyber512"
    ALG_DIL   = "ML-DSA-44"
    session = protocol = None
    try:
        bob_sock = Socket(sock=client_sock)
        protocol = PQCProtocol(ALG_KYBER, ALG_DIL, bob_sock)
        protocol.sign_module.load_keypair("cert/bob.pub", "cert/bob.key")
        protocol.sign_module.load_certificate("cert/bob.crt")
        protocol.server_handshake()
        session = SessionModule(protocol)
        session.start_session()
        log.info(f"[{addr}] Successful handshake.")
    except Exception as e:
        log.error(f"[{addr}] errors : {e}")
    finally:
        if session:   session.close()
        elif protocol: protocol.close()
        elif client_sock: client_sock.close()
        log.info(f"[{addr}] Closed thread.")


def run_server_console():
    setup_logger("Bob")
    HOST, PORT = "0.0.0.0", 65432
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(200)   # backlog augmenté pour le stress test
    log.info(f"Bob listens on {PORT} (multi-thread)...")

    while True:
        try:
            client_sock, addr = server_sock.accept()
            log.info(f"Connection from {addr}")
            threading.Thread(
                target=manage_client_thread,
                args=(client_sock, addr),
                daemon=True,
            ).start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            log.error(f"errors accept : {e}")

    server_sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PQC Stress Test Framework")
    parser.add_argument("--server", action="store_true")
    parser.add_argument("--client", action="store_true")
    parser.add_argument("--ip",    type=str, default="192.168.174.181")
    parser.add_argument("--count", "-c", type=int, default=10)
    args = parser.parse_args()

    if args.server:
        run_server_console()
    elif args.client:
        run_client_console(args.ip, args.count)
    else:
        print("Roles --server ou --client.")