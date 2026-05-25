
# PQC Chat Application

## Global Description
The **PQC Chat Application** is a prototype messaging program based on a client-server TLS1.3 model that implements Post-Quantum Cryptography (PQC) mechanisms to protect communications. The application allows users to communicate securely, offering a choice between a standard command-line interface (console) and an advanced Textual User Interface (TUI).

## Pre-required

1.	Dependencies 
"""bash
sudo apt update
sudo apt install -y git cmake ninja-build libssl-dev 
"""



2.	Liboqs library
Following official documentation and readapted according to VMs resources.

"""bash
git clone --depth=1 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build --parallel 1
cmake --build liboqs/build --target install

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
export OQS_INSTALL_PATH=/path/to/liboqs
"""

The project must be cloned from official Github page (here getting only the last version) and compiled with cmake in a specific file called liboqs/build, the parameter -DBUILD_SHARED_LIBS=ON  is used to create a shared libraries so other programs can use it.
The project is compiled using –build, the parameter –parallel referees to the number of processes to use, here the VMs are limited to 1.
Last cmake command will install the compiled files into the systems files so it can be recognized.
Finally, path to the library is declared.

3.	Wrapper liboqs-python
Wrapper can be cloned or directly installed with pip.
By cloning, you have access to the latest version, which is not the case if pip install which provides an ulterior stable ver-sion .
"""bash
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python
pip install .

export PYTHONPATH=$PYTHONPATH:/path/to/liboqs-python
or in python venv
pip install liboqs-python --break-system-packages

"""
4. Create cert and CSR

"""bash
openssl genpkey -algorithm p384_mldsa65 -provider oqsprovider -provider default -out cert/bob.key

openssl req -new -key cert/bob.key -subj "/CN=Bob" -out cert/bob.csr

"""

## Launch application modes

PQC Chat Application
"""bash
options:
  -h, --help       show this help message and exit
  --server         Run in server mode (Bob)
  --client         Run in client mode (Alice)
  --ip IP          Target IP for client
  -I, --interface  Use TUI interface (Textual) instead of console

"""

Depending on the configuration specified at launch, `com_pqc.py` will call one of these four main functions:
*  ``python3 com_pqc.py --server -I` **`run_server()`**: Starts the application in Server mode using the TUI interface.
*   **`run_client(target_ip)`**: Starts the application in Client mode using the TUI interface, targeting the specified server IP.
*   **`run_server_console()`**: Starts the server in a minimalist console mode, setting up a logger configured for 'Bob'.
*   **`run_client_console(target_ip)`**: Starts the client in console mode, setting up a logger configured for 'Alice'.

## Project Architecture
The project is modularly architected into several distinct subdirectories to separate network operations, cryptographic protocols, and visual interfaces.

### 1. `sec/` (Security and Cryptography)
This package handles all the post-quantum data protection logic.
*   **`orchestrator.py`**: Exposes the `PQCProtocol` class which orchestrates the end-to-end cryptographic handshake between the client and the server.
*   **`kem_module.py`**: Manages Key Encapsulation Mechanisms (KEM) operations relying on the `oqs` library.
*   **`sign_module.py`**: Handles post-quantum cryptographic signatures using `oqs`.
*   **`symmetric_module.py`**: Implements symmetric encryption of the actual messages using the `AESGCM` algorithm.
*   **`derive.py`**: Contains functions for secret key derivation (`derive_keys`) and generating/verifying the final MACs (`generate_finished_mac`, `verify_finished_mac`) that validate session integrity.

### 2. `net/` (Network and Transport)
Manages the transmission and reception of packets across the network.
*   **`socket_layer.py`**: Contains the `Socket` class that abstracts the TCP socket. It manages message framing by adding a 4-byte header to indicate the message length.
*   **`message_queue.py`**: Defines the `MessageQueueManager` which isolates asynchronous flows with an `incoming_queue` and an `outgoing_queue`.
*   **`protocol_handler.py`**: Provides the `ProtocolHandler` component to link the message queues to the ongoing protocol.

### 3. `session/` (Session Management)
*   **`session.py`**: Defines the `SessionModule` class, bridging network queues, background threading, and the protocol handler.

### 4. `tui/` (Textual User Interface)
The visual interface is built with the Python framework `Textual`.
*   **`ui.py`**: Hosts the base `UserInterface` application class. It consists of several screens, notably the **`ConfScreen`** (for selecting roles and cryptographic algorithms) and the **`ChatScreen`** (for sending and receiving messages).

### 5. `logger/` (Logging)
*   **`logger.py`**: Manages application logs via the `setup_logger` function, routing outputs to files like `alice.log`, `bob.log`, or `app.log` depending on the role. It also includes secure formatting methods like **`safe_key_hash`** (using `hashlib.sha256` to keep only the first 8 characters of a key's fingerprint, preventing secret exposure in the logs).

### 6. Additional Directories
*   **`cert/`**: A folder containing static cryptographic material (e.g., `bob.crt`, `bob.csr`, `bob.key`, `bob.pub`) used for authentication.
*   **`test/`**: Contains scripts for testing individual module behaviors or the user interface (e.g., `ui_test.py`).

## Main Dependencies
Based on the imports found in the source code, this project requires the following major libraries:
*   **`liboqs-python`** (`import oqs`) for all post-quantum primitives (KEM and Signatures).
*   **`cryptography`** for standard symmetric encryption components like AES-GCM.
*   **`textual`** for rendering the UI elements in the terminal.