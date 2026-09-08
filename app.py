import base64
import json
import os
import socket
import struct
import sys
import threading

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QFormLayout, QHBoxLayout, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QPushButton, QStackedWidget,
    QTextEdit, QVBoxLayout, QWidget
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_768

PROTOCOL_INFO = b"MKEM-Link-v0.1"
AAD = b"MKEM-Link"


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def derive_key(shared_secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=PROTOCOL_INFO).derive(shared_secret)


def send_packet(sock: socket.socket, payload: dict) -> None:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack("!I", len(raw)) + raw)


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            raise ConnectionError("Connection closed")
        chunks.extend(chunk)
    return bytes(chunks)


def recv_packet(sock: socket.socket) -> dict:
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    if size > 8 * 1024 * 1024:
        raise ValueError("Packet too large")
    return json.loads(recv_exact(sock, size).decode("utf-8"))


class Bridge(QObject):
    message = Signal(str)
    status = Signal(str)
    error = Signal(str)
    connected = Signal()


class SecurePeer:
    def __init__(self, bridge: Bridge):
        self.bridge = bridge
        self.sock = None
        self.aes = None
        self.running = False

    def host(self, port: int):
        threading.Thread(target=self._host, args=(port,), daemon=True).start()

    def _host(self, port: int):
        server = None
        try:
            self.bridge.status.emit(f"Listening on port {port}…")
            ek, dk = ML_KEM_768.keygen()
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", port))
            server.listen(1)
            sock, address = server.accept()
            self.sock = sock
            self.bridge.status.emit(f"Peer connected: {address[0]}")
            send_packet(sock, {"type": "kem_public", "key": b64e(ek)})
            packet = recv_packet(sock)
            if packet.get("type") != "kem_ciphertext":
                raise ValueError("Unexpected handshake packet")
            shared = ML_KEM_768.decaps(dk, b64d(packet["ciphertext"]))
            self.aes = AESGCM(derive_key(shared))
            send_packet(sock, {"type": "ready"})
            self.running = True
            self.bridge.connected.emit()
            self.bridge.status.emit("Secure channel established · ML-KEM-768 + AES-256-GCM")
            self._receive_loop()
        except Exception as exc:
            self.bridge.error.emit(str(exc))
        finally:
            if server:
                server.close()

    def connect(self, host: str, port: int):
        threading.Thread(target=self._connect, args=(host, port), daemon=True).start()

    def _connect(self, host: str, port: int):
        try:
            self.bridge.status.emit(f"Connecting to {host}:{port}…")
            sock = socket.create_connection((host, port), timeout=15)
            sock.settimeout(None)
            self.sock = sock
            packet = recv_packet(sock)
            if packet.get("type") != "kem_public":
                raise ValueError("Unexpected handshake packet")
            ek = b64d(packet["key"])
            shared, ciphertext = ML_KEM_768.encaps(ek)
            send_packet(sock, {"type": "kem_ciphertext", "ciphertext": b64e(ciphertext)})
            packet = recv_packet(sock)
            if packet.get("type") != "ready":
                raise ValueError("Handshake did not complete")
            self.aes = AESGCM(derive_key(shared))
            self.running = True
            self.bridge.connected.emit()
            self.bridge.status.emit("Secure channel established · ML-KEM-768 + AES-256-GCM")
            self._receive_loop()
        except Exception as exc:
            self.bridge.error.emit(str(exc))

    def send_message(self, text: str):
        if not self.sock or not self.aes:
            raise RuntimeError("Secure channel is not connected")
        nonce = os.urandom(12)
        ciphertext = self.aes.encrypt(nonce, text.encode("utf-8"), AAD)
        send_packet(self.sock, {"type": "message", "nonce": b64e(nonce), "ciphertext": b64e(ciphertext)})

    def _receive_loop(self):
        try:
            while self.running and self.sock:
                packet = recv_packet(self.sock)
                if packet.get("type") == "message":
                    plaintext = self.aes.decrypt(b64d(packet["nonce"]), b64d(packet["ciphertext"]), AAD)
                    self.bridge.message.emit(plaintext.decode("utf-8"))
        except Exception as exc:
            if self.running:
                self.bridge.status.emit(f"Disconnected: {exc}")
        finally:
            self.running = False


class MKEMLink(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MKEM Link")
        self.resize(920, 650)
        self.bridge = Bridge()
        self.peer = SecurePeer(self.bridge)
        self.bridge.message.connect(self.receive_message)
        self.bridge.status.connect(self.set_status)
        self.bridge.error.connect(self.show_error)
        self.bridge.connected.connect(lambda: self.stack.setCurrentWidget(self.chat_page))
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        self.home_page = self.build_home()
        self.connect_page = self.build_connect()
        self.chat_page = self.build_chat()
        self.settings_page = self.build_settings()
        for page in (self.home_page, self.connect_page, self.chat_page, self.settings_page):
            self.stack.addWidget(page)
        self.apply_style()

    def build_home(self):
        page = QWidget(); layout = QVBoxLayout(page)
        layout.addStretch()
        title = QLabel("MKEM Link"); title.setObjectName("title"); title.setAlignment(4)
        subtitle = QLabel("Simple. Secure. Post-Quantum."); subtitle.setObjectName("subtitle"); subtitle.setAlignment(4)
        desc = QLabel("Encrypted peer-to-peer communication using ML-KEM-768 for key establishment and AES-256-GCM for messages.")
        desc.setWordWrap(True); desc.setAlignment(4); desc.setMaximumWidth(620)
        row = QHBoxLayout()
        start = QPushButton("Start Chat\nConnect to a peer"); start.clicked.connect(lambda: self.stack.setCurrentWidget(self.connect_page))
        host = QPushButton("Host\nWait for a peer"); host.clicked.connect(self.start_host)
        row.addWidget(start); row.addWidget(host)
        bottom = QHBoxLayout()
        settings = QPushButton("Settings"); settings.clicked.connect(lambda: self.stack.setCurrentWidget(self.settings_page))
        about = QPushButton("About"); about.clicked.connect(self.show_about)
        self.home_status = QLabel("● Ready")
        bottom.addWidget(settings); bottom.addWidget(about); bottom.addStretch(); bottom.addWidget(self.home_status)
        layout.addWidget(title); layout.addWidget(subtitle); layout.addSpacing(12); layout.addWidget(desc, alignment=4); layout.addSpacing(28); layout.addLayout(row); layout.addStretch(); layout.addLayout(bottom)
        return page

    def build_connect(self):
        page = QWidget(); layout = QVBoxLayout(page)
        back = QPushButton("← Back"); back.clicked.connect(lambda: self.stack.setCurrentWidget(self.home_page))
        layout.addWidget(back, alignment=1)
        heading = QLabel("Connect Securely"); heading.setObjectName("heading")
        layout.addWidget(heading); layout.addSpacing(20)
        form = QFormLayout(); self.host_input = QLineEdit("127.0.0.1"); self.port_input = QLineEdit("8000")
        form.addRow("Server address", self.host_input); form.addRow("Port", self.port_input); layout.addLayout(form)
        connect = QPushButton("Connect Securely"); connect.clicked.connect(self.start_client); layout.addWidget(connect)
        self.connect_status = QLabel("Ready"); self.connect_status.setWordWrap(True); layout.addWidget(self.connect_status); layout.addStretch()
        return page

    def build_chat(self):
        page = QWidget(); layout = QVBoxLayout(page)
        top = QHBoxLayout(); heading = QLabel("Secure Chat"); heading.setObjectName("heading"); self.chat_status = QLabel("Establishing secure channel…")
        top.addWidget(heading); top.addStretch(); top.addWidget(self.chat_status); layout.addLayout(top)
        self.messages = QTextEdit(); self.messages.setReadOnly(True); layout.addWidget(self.messages)
        row = QHBoxLayout(); self.message_input = QLineEdit(); self.message_input.setPlaceholderText("Type an encrypted message…"); self.message_input.returnPressed.connect(self.send_message)
        send = QPushButton("Send"); send.clicked.connect(self.send_message); row.addWidget(self.message_input); row.addWidget(send); layout.addLayout(row)
        footer = QLabel("ML-KEM-768 key establishment · AES-256-GCM authenticated encryption"); footer.setAlignment(4); layout.addWidget(footer)
        return page

    def build_settings(self):
        page = QWidget(); layout = QVBoxLayout(page)
        back = QPushButton("← Back"); back.clicked.connect(lambda: self.stack.setCurrentWidget(self.home_page)); layout.addWidget(back, alignment=1)
        heading = QLabel("Settings"); heading.setObjectName("heading"); layout.addWidget(heading)
        layout.addWidget(QLabel("Key establishment: Post-Quantum (ML-KEM-768)")); layout.addWidget(QLabel("Message encryption: AES-256-GCM")); layout.addWidget(QCheckBox("Show secure-channel status")); layout.addStretch()
        return page

    def start_host(self):
        self.home_status.setText("● Waiting for peer")
        self.peer.host(8000)

    def start_client(self):
        try:
            port = int(self.port_input.text())
        except ValueError:
            return self.show_error("Port must be a number")
        self.peer.connect(self.host_input.text().strip(), port)

    def send_message(self):
        text = self.message_input.text().strip()
        if not text:
            return
        try:
            self.peer.send_message(text)
            self.messages.append(f"<b>You:</b> {text}")
            self.message_input.clear()
        except Exception as exc:
            self.show_error(str(exc))

    def receive_message(self, text: str):
        self.messages.append(f"<b>Peer:</b> {text}")

    def set_status(self, text: str):
        self.home_status.setText(text); self.connect_status.setText(text); self.chat_status.setText(text)

    def show_error(self, text: str):
        QMessageBox.critical(self, "MKEM Link", text)

    def show_about(self):
        QMessageBox.information(self, "About MKEM Link", "MKEM Link is a research prototype for post-quantum secure communication.\n\nML-KEM-768 establishes shared keying material. HKDF-SHA-256 derives the session key. AES-256-GCM protects application messages.\n\nThis prototype is not security-audited and is not intended for production use.")

    def apply_style(self):
        self.setStyleSheet("""
            QMainWindow, QWidget { background: #f7f8fa; color: #17202a; font-size: 15px; }
            QLabel#title { font-size: 42px; font-weight: 700; }
            QLabel#subtitle { font-size: 20px; color: #566573; }
            QLabel#heading { font-size: 28px; font-weight: 700; }
            QPushButton { background: white; border: 1px solid #d5d8dc; border-radius: 12px; padding: 14px 22px; font-weight: 600; }
            QPushButton:hover { background: #eef2f5; }
            QLineEdit, QTextEdit { background: white; border: 1px solid #d5d8dc; border-radius: 10px; padding: 10px; }
        """)


def main():
    app = QApplication(sys.argv)
    window = MKEMLink(); window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
