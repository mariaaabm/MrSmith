"""
MR.SMITH - Cliente TUI (Textual)
Interface gráfica em terminal com estética cyber-noir.

Corre com: python3 client_tui.py
Requer:    pip install textual
"""

import json
import socket
import sys
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Header, Footer, Label, Input, Button, DataTable,
    Static, ListView, ListItem, Select, RadioButton, RadioSet,
)

from crypto_utils import (
    encode_b64, decode_b64,
    create_hmac_sha256, verify_hmac_sha256,
    generate_symmetric_key,
    encrypt_with_aes_gcm, decrypt_with_aes_gcm,
    encrypt_with_cipher, decrypt_with_cipher,
    verify_signature, hash_password,
    generate_rsa_key_pair, decrypt_with_rsa_oaep,
    derive_session_kek, SUPPORTED_CIPHERS,
)

from client import HELP_TEXTS


# IP do servidor: pode ser passado como argumento (ex.: python3 client_tui.py 192.168.1.50).
# Default: localhost.
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = 5000

INBOX_DIR = Path("inbox")
KEYS_DIR = Path("client_keys")
INBOX_DIR.mkdir(exist_ok=True)
KEYS_DIR.mkdir(exist_ok=True)


# =========================================================================
# Protocolo (funções puras — sem I/O na stdin/stdout)
# =========================================================================

def send_json(conn, data):
    message = json.dumps(data).encode("utf-8")
    conn.sendall(len(message).to_bytes(4, "big") + message)


def recv_json(conn):
    size_data = conn.recv(4)
    if not size_data:
        return None
    size = int.from_bytes(size_data, "big")
    message = b""
    while len(message) < size:
        chunk = conn.recv(size - len(message))
        if not chunk:
            return None
        message += chunk
    return json.loads(message.decode("utf-8"))


def save_local_seed(username, password, seed_b64):
    salt_b64, derived_key_b64 = hash_password(password)
    blob = encrypt_with_aes_gcm(seed_b64.encode("utf-8"), derived_key_b64)
    seed_file = KEYS_DIR / f"{username}.seed"
    with open(seed_file, "w", encoding="utf-8") as file:
        json.dump({"salt": salt_b64, "blob": blob}, file, indent=4)


def load_local_seed(username, password):
    seed_file = KEYS_DIR / f"{username}.seed"
    if not seed_file.exists():
        raise FileNotFoundError(
            f"Seed local não encontrada em {seed_file}. Regista-te neste computador."
        )
    with open(seed_file, "r", encoding="utf-8") as file:
        data = json.load(file)
    salt_bytes = decode_b64(data["salt"])
    _, derived_key_b64 = hash_password(password, salt_bytes)
    seed_bytes = decrypt_with_aes_gcm(data["blob"], derived_key_b64)
    return seed_bytes.decode("utf-8")


def protocol_register(conn, username, password):
    salt_b64, password_hash_b64 = hash_password(password)
    private_pem, public_pem = generate_rsa_key_pair()
    send_json(conn, {
        "action": "register",
        "username": username,
        "salt": salt_b64,
        "password_hash": password_hash_b64,
        "public_key_pem": encode_b64(public_pem),
    })
    response = recv_json(conn)
    if response["status"] == "ok":
        seed_bytes = decrypt_with_rsa_oaep(response["encrypted_seed"], private_pem)
        save_local_seed(username, password, seed_bytes.decode("utf-8"))
    return response


def protocol_login(conn, username, password):
    """Devolve (kek_b64, counter). Levanta Exception se falhar."""
    send_json(conn, {"action": "login_init", "username": username})
    init_resp = recv_json(conn)
    if init_resp["status"] != "ok":
        raise Exception(init_resp.get("message", "Erro no login_init"))

    salt_bytes = decode_b64(init_resp["salt"])
    nonce_bytes = decode_b64(init_resp["nonce"])
    _, pwd_hash_b64 = hash_password(password, salt_bytes)
    proof_b64 = create_hmac_sha256(nonce_bytes, pwd_hash_b64)

    send_json(conn, {
        "action": "login_proof",
        "username": username,
        "proof": proof_b64,
    })
    resp = recv_json(conn)
    if resp["status"] != "ok":
        raise Exception(resp.get("message", "Login falhou"))

    seed_b64 = load_local_seed(username, password)
    counter = resp["login_counter"]
    kek = derive_session_kek(seed_b64, counter)
    return kek, counter


def protocol_list_online(conn, exclude=None):
    send_json(conn, {"action": "list_online"})
    resp = recv_json(conn)
    if resp["status"] != "ok":
        return []
    users = resp.get("users", [])
    if exclude:
        users = [u for u in users if u != exclude]
    return users


def protocol_send_plain(conn, kek, recipient, file_path):
    file_bytes = Path(file_path).read_bytes()
    mac = create_hmac_sha256(file_bytes, kek)
    send_json(conn, {
        "action": "send_plain_file",
        "recipient": recipient,
        "filename": Path(file_path).name,
        "file_b64": encode_b64(file_bytes),
        "hmac": mac,
    })
    return recv_json(conn)


def protocol_send_encrypted(conn, kek, recipient, file_path, cipher):
    file_bytes = Path(file_path).read_bytes()
    key_size = SUPPORTED_CIPHERS[cipher]
    session_key = generate_symmetric_key(size_bytes=key_size)
    encrypted_file = encrypt_with_cipher(file_bytes, session_key, cipher)
    encrypted_session_key = encrypt_with_aes_gcm(session_key.encode("utf-8"), kek)
    send_json(conn, {
        "action": "send_encrypted_file",
        "recipient": recipient,
        "filename": Path(file_path).name,
        "cipher": cipher,
        "encrypted_file": encrypted_file,
        "encrypted_session_key_for_agent": encrypted_session_key,
    })
    return recv_json(conn)


def protocol_send_signed(conn, recipient, file_path):
    file_bytes = Path(file_path).read_bytes()
    send_json(conn, {
        "action": "send_signed_file",
        "recipient": recipient,
        "filename": Path(file_path).name,
        "file_b64": encode_b64(file_bytes),
    })
    return recv_json(conn)


def protocol_list_inbox(conn):
    send_json(conn, {"action": "list_inbox"})
    resp = recv_json(conn)
    return resp.get("files", [])


def protocol_download_file(conn, kek, index):
    """Devolve tuple (status_string, output_path | None)."""
    send_json(conn, {"action": "download_file", "index": index})
    resp = recv_json(conn)
    if resp["status"] != "ok":
        return resp["message"], None

    file_info = resp["file"]
    sender = file_info["sender"]
    filename = file_info["filename"]
    ftype = file_info["type"]

    if ftype == "plain":
        file_bytes = decode_b64(file_info["file_b64"])
        valid = verify_hmac_sha256(file_bytes, kek, file_info["hmac"])
        out = INBOX_DIR / f"received_from_{sender}_{filename}"
        out.write_bytes(file_bytes)
        return (f"HMAC {'OK' if valid else 'INVÁLIDO'} — guardado em {out}"), out

    if ftype == "encrypted":
        cipher = file_info.get("cipher", "AES-256-GCM")
        try:
            sk_bytes = decrypt_with_aes_gcm(file_info["encrypted_session_key"], kek)
            sk = sk_bytes.decode("utf-8")
            file_bytes = decrypt_with_cipher(file_info["encrypted_file"], sk, cipher)
            out = INBOX_DIR / f"decrypted_from_{sender}_{filename}"
            out.write_bytes(file_bytes)
            return (f"{cipher} OK — guardado em {out}"), out
        except Exception as error:
            return f"Erro a decifrar: {error}", None

    if ftype == "signed":
        file_bytes = decode_b64(file_info["file_b64"])
        public_key = decode_b64(file_info["public_key"])
        valid = verify_signature(file_bytes, file_info["signature"], public_key)
        out = INBOX_DIR / f"signed_from_{sender}_{filename}"
        out.write_bytes(file_bytes)
        return (
            f"Assinatura {'VÁLIDA' if valid else 'INVÁLIDA'} — guardado em {out}"
        ), out

    return "Tipo de ficheiro desconhecido", None


def protocol_logout(conn):
    try:
        send_json(conn, {"action": "logout"})
        recv_json(conn)
    except Exception:
        pass


# =========================================================================
# Screens
# =========================================================================

class LoginScreen(Screen):
    BINDINGS = [("escape", "app.quit", "Sair")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="login-container"):
            with Vertical(id="login-card"):
                yield Static("MR.SMITH", classes="brand-title")
                yield Static("Plataforma de partilha segura de ficheiros", classes="brand-sub")

                yield Static("Utilizador", classes="label-caps")
                yield Input(placeholder="username", id="username")

                yield Static("Password", classes="label-caps")
                yield Input(placeholder="••••••••", password=True, id="password")

                with Horizontal(id="actions"):
                    yield Button("Registar", id="btn-register")
                    yield Button(
                        "Entrar",
                        id="btn-login",
                        variant="primary",
                    )
                yield Static("", id="login-status", classes="status")
        yield Footer()

    def show_status(self, message: str, ok: bool) -> None:
        widget = self.query_one("#login-status", Static)
        widget.update(message)
        widget.set_classes("status " + ("status-ok" if ok else "status-error"))

    @work(thread=True, exclusive=True)
    def do_register(self, username: str, password: str) -> None:
        try:
            response = protocol_register(self.app.conn, username, password)
            ok = response["status"] == "ok"
            self.app.call_from_thread(self.show_status, response["message"], ok)
        except Exception as error:
            self.app.call_from_thread(self.show_status, f"Erro: {error}", False)

    @work(thread=True, exclusive=True)
    def do_login(self, username: str, password: str) -> None:
        try:
            kek, counter = protocol_login(self.app.conn, username, password)
            self.app.username = username
            self.app.kek_session = kek
            self.app.login_counter = counter
            self.app.call_from_thread(self.go_to_dashboard)
        except Exception as error:
            self.app.call_from_thread(self.show_status, f"{error}", False)

    def go_to_dashboard(self) -> None:
        self.app.push_screen("dashboard")
        self.show_status(
            f"Login OK. Counter = {self.app.login_counter}.", True
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        username = self.query_one("#username", Input).value.strip()
        password = self.query_one("#password", Input).value
        if not username or not password:
            self.show_status("Username e password obrigatórios.", False)
            return

        if event.button.id == "btn-register":
            self.show_status("A registar...", True)
            self.do_register(username, password)
        elif event.button.id == "btn-login":
            self.show_status("A autenticar...", True)
            self.do_login(username, password)


class DashboardScreen(Screen):
    BINDINGS = [
        ("ctrl+i", "inbox", "Inbox"),
        ("ctrl+h", "help", "Help"),
        ("ctrl+l", "logout", "Logout"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="dashboard-layout"):
            # Left: online users
            with Vertical(id="left-sidebar", classes="card"):
                yield Static("Online", classes="card-title")
                yield ListView(id="online-list")

            # Center: file operations
            with Vertical(id="main-area", classes="card"):
                yield Static("Enviar ficheiro", classes="card-title")
                yield Static("Ficheiro:", classes="label-caps")
                yield Input(placeholder="sent/segredo.txt", id="file-path")
                yield Static("Destinatário:", classes="label-caps")
                yield Input(placeholder="bob", id="recipient")
                yield Static("Modo:", classes="label-caps")
                with RadioSet(id="mode-set"):
                    yield RadioButton("HMAC (em claro)", id="mode-hmac", value=True)
                    yield RadioButton("Cifrado (AES-GCM / ChaCha20)", id="mode-encrypted")
                    yield RadioButton("Assinado pelo Mr. Smith", id="mode-signed")
                yield Button(
                    "Enviar",
                    id="btn-send",
                    variant="primary",
                )
                yield Static("", id="send-status", classes="status")

            # Right: cipher config
            with Vertical(id="right-sidebar", classes="card"):
                yield Static("Configuração", classes="card-title")
                yield Static("Cifra", classes="label-caps")
                yield Select(
                    [(c, c) for c in SUPPORTED_CIPHERS.keys()],
                    value="AES-256-GCM",
                    id="cipher-select",
                    allow_blank=False,
                )
                yield Static("Tamanho de chave (automático)", classes="label-caps subtle")
                yield Static("16 / 24 / 32 bytes conforme cifra", classes="subtle")
                yield Static("Sessão", classes="label-caps")
                yield Static("", id="session-info", classes="subtle")
        yield Footer()

    def on_mount(self) -> None:
        info = self.query_one("#session-info", Static)
        info.update(
            f"user: {self.app.username}\ncounter: {self.app.login_counter}"
        )
        self.refresh_online()
        self.set_interval(5.0, self.refresh_online)

    @work(thread=True)
    def refresh_online(self) -> None:
        users = protocol_list_online(self.app.conn, exclude=self.app.username)
        self.app.call_from_thread(self.update_online_list, users)

    def update_online_list(self, users) -> None:
        lv = self.query_one("#online-list", ListView)
        lv.clear()
        if not users:
            lv.append(ListItem(Label("(ninguém online)")))
            return
        for user in users:
            lv.append(ListItem(Label(f"● {user}")))

    def show_send_status(self, message: str, ok: bool) -> None:
        widget = self.query_one("#send-status", Static)
        widget.update(message)
        widget.set_classes("status " + ("status-ok" if ok else "status-error"))

    @work(thread=True, exclusive=True)
    def do_send(self, mode: str, recipient: str, path: str, cipher: str) -> None:
        try:
            if mode == "mode-hmac":
                resp = protocol_send_plain(
                    self.app.conn, self.app.kek_session, recipient, path
                )
            elif mode == "mode-encrypted":
                resp = protocol_send_encrypted(
                    self.app.conn, self.app.kek_session, recipient, path, cipher
                )
            elif mode == "mode-signed":
                resp = protocol_send_signed(self.app.conn, recipient, path)
            else:
                resp = {"status": "error", "message": "Modo desconhecido."}

            ok = resp["status"] == "ok"
            self.app.call_from_thread(self.show_send_status, resp["message"], ok)
        except Exception as error:
            self.app.call_from_thread(
                self.show_send_status, f"Erro: {error}", False
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "btn-send":
            return

        path = self.query_one("#file-path", Input).value.strip()
        recipient = self.query_one("#recipient", Input).value.strip()
        cipher = str(self.query_one("#cipher-select", Select).value)

        mode_set = self.query_one("#mode-set", RadioSet)
        pressed = mode_set.pressed_button
        mode_id = pressed.id if pressed else "mode-hmac"

        if not path or not recipient:
            self.show_send_status("Path e recipient obrigatórios.", False)
            return
        if not Path(path).exists():
            self.show_send_status(f"Ficheiro não existe: {path}", False)
            return

        self.show_send_status("A enviar...", True)
        self.do_send(mode_id, recipient, path, cipher)

    def action_inbox(self) -> None:
        self.app.push_screen("inbox")

    def action_help(self) -> None:
        self.app.push_screen("help")

    def action_logout(self) -> None:
        protocol_logout(self.app.conn)
        self.app.username = None
        self.app.kek_session = None
        self.app.login_counter = 0
        self.app.pop_screen()


class InboxScreen(Screen):
    BINDINGS = [
        ("escape", "back", "Voltar"),
        ("r", "refresh", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="inbox-container", classes="card"):
            yield Static("Caixa de entrada", classes="card-title")
            with Horizontal():
                yield Button("Atualizar", id="btn-refresh")
            yield DataTable(id="inbox-table")
            yield Static(
                "Dica: setas/clica numa linha + Enter para receber.",
                classes="subtle",
            )
            yield Static("", id="inbox-status", classes="status")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#inbox-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Nº", "De", "Tipo", "Ficheiro")
        self.action_refresh()

    @work(thread=True)
    def action_refresh(self) -> None:
        files = protocol_list_inbox(self.app.conn)
        self.app.call_from_thread(self.update_table, files)

    def update_table(self, files) -> None:
        table = self.query_one("#inbox-table", DataTable)
        table.clear()
        for file_info in files:
            table.add_row(
                str(file_info["index"]),
                file_info["sender"],
                file_info["type"],
                file_info["filename"],
            )
        status = self.query_one("#inbox-status", Static)
        if not files:
            status.update("(caixa vazia)")
            status.set_classes("status subtle")
        else:
            status.update(f"{len(files)} ficheiro(s) pendente(s)")
            status.set_classes("status status-ok")

    @work(thread=True, exclusive=True)
    def do_download(self, index: int) -> None:
        message, _ = protocol_download_file(self.app.conn, self.app.kek_session, index)
        ok = "INVÁLID" not in message and "Erro" not in message
        self.app.call_from_thread(self.set_status, message, ok)
        self.app.call_from_thread(self.action_refresh)

    def set_status(self, message: str, ok: bool) -> None:
        status = self.query_one("#inbox-status", Static)
        status.update(message)
        status.set_classes("status " + ("status-ok" if ok else "status-error"))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        table = event.data_table
        row = table.get_row(event.row_key)
        try:
            file_index = int(row[0])
        except (ValueError, IndexError):
            return
        self.set_status(f"A receber ficheiro #{file_index}...", True)
        self.do_download(file_index)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-refresh":
            self.action_refresh()

    def action_back(self) -> None:
        self.app.pop_screen()


class HelpScreen(Screen):
    BINDINGS = [("escape", "back", "Voltar")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="help-layout"):
            with Vertical(id="help-sidebar", classes="card"):
                yield Static("Tópicos", classes="card-title")
                for key, (title, _) in HELP_TEXTS.items():
                    yield Button(title, id=f"help-{key}")
            with Vertical(id="help-content", classes="card"):
                yield Static("Conteúdo", classes="card-title")
                yield Static(
                    "Escolhe um tópico no painel da esquerda.",
                    id="help-content-text",
                )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id and event.button.id.startswith("help-"):
            key = event.button.id.split("-", 1)[1]
            if key in HELP_TEXTS:
                _, content = HELP_TEXTS[key]
                self.query_one("#help-content-text", Static).update(content)

    def action_back(self) -> None:
        self.app.pop_screen()


# =========================================================================
# App
# =========================================================================

class MrSmithApp(App):
    TITLE = "MR.SMITH"
    SUB_TITLE = "Plataforma de partilha segura"

    SCREENS = {
        "dashboard": DashboardScreen,
        "inbox": InboxScreen,
        "help": HelpScreen,
    }

    def __init__(self) -> None:
        super().__init__()
        self.conn: socket.socket | None = None
        self.username: str | None = None
        self.kek_session: str | None = None
        self.login_counter: int = 0

    def on_mount(self) -> None:
        try:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((HOST, PORT))
        except Exception as error:
            self.exit(message=f"Não consegui ligar ao servidor {HOST}:{PORT}: {error}")
            return
        self.push_screen(LoginScreen())

    def on_unmount(self) -> None:
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass


def main() -> None:
    app = MrSmithApp()
    app.run()


if __name__ == "__main__":
    main()
