import time
from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, Label, Input, Button, Select, RichLog,Static
from textual.containers import Horizontal, Vertical, Container
from textual.widget import Widget
import logging
from net import Socket
from sec import PQCProtocol
from session import SessionModule
import socket
from textual import work
from logger import Logger, setup_logger


log = logging.getLogger(__name__)


class ConfScreen(Screen):
    "Configuration Screen for selecting role and algorithms"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Vertical(id="conf-screen")
        yield Static(
            "[bold #89b4fa]╔════════════════════════════════════╗[/]\n"
            "[bold #89b4fa]║  Post-Quantum Cryptography Setup   ║[/]\n"
            "[bold #89b4fa]╚════════════════════════════════════╝[/]",
            id="title"
        )
        yield Select(
            options=[("Client", "client"), ("Server", "server")],
            prompt="Select Role",
            id="role-select"
        )
        yield Input(placeholder="Enter IP address", id="ip-input")

        yield Select(
            options=[("Kyber512", "Kyber512"), ("Kyber768", "Kyber768"), ("Kyber1024", "Kyber1024")],
            prompt="Select KEM Algorithm",
            id="kem-select"
        )
        yield Select(
            options=[("ML-DSA-44", "ML-DSA-44"), ("ML-DSA-65", "ML-DSA-65"), ("ML-DSA-87", "ML-DSA-87")],
            prompt="Select Signature Algorithm",
            id="sig-select"
        )
        yield Button("Start Chat", id="start-btn")

        yield Footer()

    def on_mount(self) -> None:
        role_select = self.query_one("#role-select", Select)
        role_select.value = self.app.default_role 

        input_ip = self.query_one("#ip-input", Input)
        if self.app.default_ip:
            input_ip.value = self.app.default_ip

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start-btn":
            role = self.query_one("#role-select", Select).value
            ip = self.query_one("#ip-input", Input).value
            kem_alg = self.query_one("#kem-select", Select).value
            sig_alg = self.query_one("#sig-select", Select).value

            log.info(f"Configuration selected - Role: {role}, IP: {ip}, KEM: {kem_alg}, Signature: {sig_alg}")
            self.app.push_screen("chat")

            #### lancer server ou client avec les paramètres sélectionnés
            if role == "server":
                self.app.run_server(ip, kem_alg, sig_alg)
            elif role == "client":
                self.app.run_client(ip, kem_alg, sig_alg)


class ChatScreen(Screen):
    "Chat Screen for sending and receiving messages"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Horizontal():
            with Vertical(id="chat-container",  markup=True):
                yield RichLog(id="chat-log",  markup=True)
                yield Input(placeholder="Type your message here...", id="msg-input")
                yield Button("Send", id="send-btn")

            with Vertical(id="monitoring"):
                yield Static("[bold #89b4fa]Monitoring Panel \n\nAlgo: --\nRTT: -- ms\nSize: -- bytes[/]", id="metrics", markup=True)
                yield RichLog(id="monitor-log",  markup=True)

        
        yield Footer()

    def on_mount(self) -> None:
        sys_logs = self.query_one("#chat-log", RichLog)
        sys_logs.write("[bold green]Waiting for PQC connections...[/]\n")

        chat = self.query_one("#chat-log", RichLog)
        chat.write("[bold cyan]Chat initialized. Ready to send and receive messages.[/]\n")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "msg-input":
            message = event.value

            chat_log = self.query_one("#chat-log", RichLog)

            ## Message through session
            if self.app.session and self.app.session._running:
                chat_log.write(f"[bold blue]Me:[/] {message}\n")
                self.app.session.sending(message.encode('utf-8')) 
                event.input.value = ""  # Clear input after sending
            else:
                chat_log.write("[bold red]Error: Session not established. Cannot send message.[/]\n")
                log.error("Attempted to send message but session is not established.")

class UserInterface(App):
    """Main application class for the PQC Chat UI."""


    CSS_PATH = "style_ui.css"
    SCREENS = {
        "conf": ConfScreen,
        "chat": ChatScreen
    }

    def __init__(self, role: str = "client", target_ip: str = ""):
        super().__init__()
        self.default_role = role
        self.default_ip = target_ip
        self.session = None  # Will hold the SessionModule instance once the session is established

        self.kem_alg = None
        self.sig_alg = None
        self.rtt    = 0.0
        self.msg_size = 0

    def on_mount(self) -> None:

        setup_logger(role=self.default_role)

        root_log = logging.getLogger()
        # root_log.setLevel(logging.INFO)

        tui_handler = Logger(self)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        tui_handler.setFormatter(formatter)
        root_log.addHandler(tui_handler)
        self.push_screen("conf")


    
    def handle_incoming_message(self, message: str, size: int):
        """Callback to handle incoming messages from the session."""
        try:
            chat_screen = self.get_screen("chat")
            chat_log = chat_screen.query_one("#chat-log", RichLog)
            chat_log.write(f"[bold magenta]Peer:[/] {message}\n")
            self.update_monitor( size=size)  # Update monitor with message size and current RTT
        except Exception as e:
            log.error(f"Error handling incoming message: {str(e)}")
            
    @work(thread=True)
    def run_server(self, ip: str, kem_alg: str, sig_alg: str):
        PORT = 65432
        log.info(f"Starting server on {ip}:{PORT} with KEM: {kem_alg} and Signature: {sig_alg}")

        listen_ip = ip if ip else "0.0.0.0"

        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind((listen_ip, PORT))
            server_socket.listen(1)

            log.info(f"Server listening on {listen_ip}:{PORT}...")
            self.call_from_thread(self.log_to_chat, f"[bold green]Server started on {listen_ip}:{PORT}[/]\nWaiting for incoming connections...")

            conn, addr = server_socket.accept()
            bob_socket = Socket(sock=conn)
            log.info(f"Connection accepted from {addr}")
            self.call_from_thread(self.log_to_chat, f"[bold green]Connection accepted from {addr}[/]\n")

            protocol = PQCProtocol(kem_alg, sig_alg, bob_socket)
            self.call_from_thread(self.log_to_chat, "[cyan]Chargement des certificats de Bob...[/]")
            protocol.sign_module.load_keypair("cert/bob.pub", "cert/bob.key")
            protocol.sign_module.load_certificate("cert/bob.crt")

            t0 = time.perf_counter()
            protocol.server_handshake()
            
            rtt = (time.perf_counter() - t0) * 1000  # Calculate RTT for handshake
            log.info(f"Server handshake completed in {rtt:.2f} ms")
            
            self.update_monitor(kem_alg=kem_alg, sig_alg=sig_alg, rtt=rtt, size="0")
            
            
            self.session = SessionModule(protocol)
            self.session.on_message_callback = self.handle_incoming_message
            self.session.start_session()

            log.info("Server handshake completed, session started.")
            self.call_from_thread(self.log_to_chat, "[bold green]Handshake completed, session started.[/]\n")

        except Exception as e:
            log.error(f"Error in server setup: {str(e)}")
            self.call_from_thread(self.log_to_chat, f"[bold red]Error starting server: {str(e)}[/]\n")

    @work(thread=True)
    def run_client(self, ip: str, kem_alg: str, sig_alg: str):
        PORT = 65432
        log.info(f"Starting client connecting to {ip}:{PORT} with KEM: {kem_alg} and Signature: {sig_alg}")

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((ip, PORT))
            log.info(f"Connected to server at {ip}:{PORT}")
            self.call_from_thread(self.log_to_chat, f"[bold green]Connected to server at {ip}:{PORT}[/]\n")

            protocol = PQCProtocol(kem_alg, sig_alg, Socket(sock=client_socket))
            
            t0 = time.perf_counter()
            protocol.client_handshake()
            rtt = (time.perf_counter() - t0) * 1000  # Calculate RTT for handshake
            log.info(f"Client handshake completed in {rtt:.2f} ms")

            self.update_monitor(kem_alg=kem_alg, sig_alg=sig_alg, rtt=rtt, size="0")
            self.session = SessionModule(protocol)
            self.session.on_message_callback = self.handle_incoming_message
            self.session.start_session()

            log.info("Client handshake completed, session started.")
            self.call_from_thread(self.log_to_chat, "[bold green]Handshake completed, session started.[/]\n")

        except Exception as e:
            log.error(f"Error in client setup: {str(e)}")
            self.call_from_thread(self.log_to_chat, f"[bold red]Error starting client: {str(e)}[/]\n")


    def log_to_chat(self, message: str):
        """Helper method to log messages to the chat log from other threads."""

        try:
            chat_sceen = self.get_screen("chat")
            chat_log = chat_sceen.query_one("#chat-log", RichLog)
            chat_log.write(message)
        except Exception as e:
            log.error(f"Error logging to chat: {str(e)}")
            pass    

    def log_to_monitor(self, message: str):
        """Helper method to log messages to the monitoring panel from other threads."""

        try:
            chat_sceen = self.get_screen("chat")
            monitor_log = chat_sceen.query_one("#monitor-log", RichLog)
            monitor_log.write(message)
        except Exception as e:
            log.error(f"Error logging to monitor: {str(e)}")
            pass

    def update_monitor(self, kem_alg: str="--", sig_alg: str="--", rtt: float = 0.0, size: int = 0):
        """Helper method to update the monitoring panel with current metrics."""
        try:
            if kem_alg: self.kem_alg = kem_alg
            if sig_alg: self.sig_alg = sig_alg
            if rtt: self.rtt = rtt
            if size: self.msg_size = size

            chat_screen = self.get_screen("chat")
            metrics_widget = chat_screen.query_one("#metrics", Static)
            new_metrics = (
                f"[bold #89b4fa]Monitoring Panel \n\nAlgo: {self.kem_alg}/ {self.sig_alg}\nRTT: {self.rtt:.2f} ms\nSize: {self.msg_size} bytes[/]"
            )

            self.call_from_thread(metrics_widget.update, new_metrics)
        except Exception as e:
            log.error(f"Error updating monitor: {str(e)}")
