import json
import socket
import sys
from getpass import getpass
from pathlib import Path

from crypto_utils import (
    encode_b64,
    decode_b64,
    create_hmac_sha256,
    verify_hmac_sha256,
    generate_symmetric_key,
    encrypt_with_aes_gcm,
    decrypt_with_aes_gcm,
    encrypt_with_cipher,
    decrypt_with_cipher,
    verify_signature,
    hash_password,
    generate_rsa_key_pair,
    decrypt_with_rsa_oaep,
    derive_session_kek,
    SUPPORTED_CIPHERS,
)

# IP do servidor que pode ser passado como argumento (ex.: python3 client.py 192.168.1.50)
# por defeito é o localhost
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = 5000

INBOX_DIR = Path("inbox")
SENT_DIR = Path("sent")
KEYS_DIR = Path("client_keys")

# Diretórios locais usados pelo cliente:
# - inbox: ficheiros recebidos
# - sent: ficheiros enviados
# - client_keys: seed local cifrado por utilizador
INBOX_DIR.mkdir(exist_ok=True)
SENT_DIR.mkdir(exist_ok=True)
KEYS_DIR.mkdir(exist_ok=True)


def save_local_seed(username: str, password: str, seed_b64: str) -> None:
    # Cifra o seed recebido do servidor com uma chave derivada da password e guarda-o localmente
    salt_b64, derived_key_b64 = hash_password(password)
    blob = encrypt_with_aes_gcm(seed_b64.encode("utf-8"), derived_key_b64)

    seed_file = KEYS_DIR / f"{username}.seed"
    with open(seed_file, "w", encoding="utf-8") as file:
        json.dump({"salt": salt_b64, "blob": blob}, file, indent=4)


def load_local_seed(username: str, password: str) -> str:
    # Lê o seed local cifrado pelo cliente e descifra-o com a password
    seed_file = KEYS_DIR / f"{username}.seed"

    if not seed_file.exists():
        raise FileNotFoundError(
            f"Seed local não encontrada em {seed_file}. "
            f"Faz registo neste computador primeiro."
        )

    with open(seed_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    salt_bytes = decode_b64(data["salt"])
    _, derived_key_b64 = hash_password(password, salt_bytes)

    seed_bytes = decrypt_with_aes_gcm(data["blob"], derived_key_b64)
    return seed_bytes.decode("utf-8")


def send_json(conn: socket.socket, data: dict) -> None:
    # Envia JSON ao servidor
    message = json.dumps(data).encode("utf-8")
    conn.sendall(len(message).to_bytes(4, "big") + message)


def recv_json(conn: socket.socket) -> dict | None:
    # Recebe JSON do servidor
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


# registo 
def register(conn: socket.socket) -> None:
    username = input("Username: ").strip()
    password = getpass("Password: ")

    # 1) PBKDF2 corre localmente — a password nunca sai daqui
    salt_b64, password_hash_b64 = hash_password(password)

    # 2) Par RSA temporário 
    private_pem, public_pem = generate_rsa_key_pair()

    send_json(conn, {
        "action": "register",
        "username": username,
        "salt": salt_b64,
        "password_hash": password_hash_b64,
        "public_key_pem": encode_b64(public_pem)
    })

    response = recv_json(conn)
    print(response["message"])

    if response["status"] != "ok":
        return

    # 3) Decifra o seed recebido via RSA-OAEP com a chave privada temporária
    seed_bytes = decrypt_with_rsa_oaep(
        response["encrypted_seed"],
        private_pem
    )
    seed_b64 = seed_bytes.decode("utf-8")

    save_local_seed(username, password, seed_b64)

    print("\nSeed estabelecido em segurança com o Mr. Smith.")
    print("(Recebido via RSA-OAEP, guardado localmente cifrado com a tua password.)")
    print()


# login 
def login(conn: socket.socket) -> tuple[str | None, str | None]:
    username = input("Username: ").strip()
    password = getpass("Password: ")

    # Fase 1: enviar o login e receber salt + nonce
    send_json(conn, {
        "action": "login_init",
        "username": username
    })

    init_response = recv_json(conn)

    if init_response["status"] != "ok":
        print(init_response.get("message", "Erro no início do login."))
        return None, None

    salt_b64 = init_response["salt"]
    nonce_b64 = init_response["nonce"]

    # Fase 2: derivar a mesma pwd_hash que o servidor tem (PBKDF2 com o mesmo salt)
    # e verificar calculando HMAC(nonce, pwd_hash)
    salt_bytes = decode_b64(salt_b64)
    _, pwd_hash_b64 = hash_password(password, salt_bytes)

    nonce_bytes = decode_b64(nonce_b64)
    proof_b64 = create_hmac_sha256(nonce_bytes, pwd_hash_b64)

    send_json(conn, {
        "action": "login_proof",
        "username": username,
        "proof": proof_b64
    })

    response = recv_json(conn)
    print(response["message"])

    if response["status"] != "ok":
        return None, None

    # Carrega o seed local (cifrado com a password) e deriva a KEK desta sessão
    try:
        seed_b64 = load_local_seed(username, password)
    except FileNotFoundError as error:
        print(f"Erro: {error}")
        return None, None

    counter = response["login_counter"]
    kek_session = derive_session_kek(seed_b64, counter)

    return username, kek_session


def list_online(conn: socket.socket) -> None:
    # Pede ao servidor a lista de utilizadores atualmente online
    send_json(conn, {
        "action": "list_online"
    })

    response = recv_json(conn)

    if response["status"] != "ok":
        print(response["message"])
        return

    users = response["users"]

    if not users:
        print("Não há outros utilizadores online.")
        return

    print("\nUtilizadores online:")
    for user in users:
        print(f"- {user}")
    print()


# envio de ficheiros
def send_plain_file(conn: socket.socket, shared_key: str) -> None:
    recipient = input("Destinatário online: ").strip()
    file_path_str = input("Caminho do ficheiro a enviar: ").strip()

    file_path = Path(file_path_str)

    if not file_path.exists() or not file_path.is_file():
        print("Ficheiro não encontrado.")
        return

    file_bytes = file_path.read_bytes()
    
    # HMAC calculado sobre o conteúdo do ficheiro
    mac = create_hmac_sha256(file_bytes, shared_key)

    send_json(conn, {
        "action": "send_plain_file",
        "recipient": recipient,
        "filename": file_path.name,
        "file_b64": encode_b64(file_bytes),
        "hmac": mac
    })

    response = recv_json(conn)
    print(response["message"])

CIPHER_CHOICES = [
    ("AES-128-GCM", "AES com chave de 128 bits, modo GCM"),
    ("AES-192-GCM", "AES com chave de 192 bits, modo GCM"),
    ("AES-256-GCM", "AES com chave de 256 bits, modo GCM (default)"),
    ("ChaCha20-Poly1305", "ChaCha20 + Poly1305 (alternativa moderna ao AES)"),
]


# escolha de cifra para envio cifrado
def choose_cipher() -> str:
    print("\nEscolhe a cifra para este ficheiro:")
    for i, (name, desc) in enumerate(CIPHER_CHOICES, start=1):
        print(f"  {i} - {name:20s} ({desc})")
    print("  [Enter] - usar default (AES-256-GCM)")

    option = input("Opção: ").strip()

    if option == "":
        return "AES-256-GCM"

    if option.isdigit():
        index = int(option) - 1
        if 0 <= index < len(CIPHER_CHOICES):
            return CIPHER_CHOICES[index][0]

    print("Opção inválida. A usar AES-256-GCM.")
    return "AES-256-GCM"


# envio de ficheiro cifrado com cifra escolhida pelo utilizador
def send_encrypted_file(conn: socket.socket, shared_key: str) -> None:
    recipient = input("Destinatário online: ").strip()
    file_path_str = input("Caminho do ficheiro a enviar: ").strip()

    file_path = Path(file_path_str)

    if not file_path.exists() or not file_path.is_file():
        print("Ficheiro não encontrado.")
        return

    file_bytes = file_path.read_bytes()

    # Escolha de cifra e tamanho de chave 
    cipher = choose_cipher()
    key_size = SUPPORTED_CIPHERS[cipher]

    # Chave de sessão: gerada pelo cliente emissor com o tamanho exigido
    # pela cifra escolhida (16/24/32 bytes)
    session_key = generate_symmetric_key(size_bytes=key_size)

    # Ficheiro cifrado com a chave de sessão usando a cifra escolhida
    encrypted_file = encrypt_with_cipher(file_bytes, session_key, cipher)

    # Chave de sessão protegida para o agente.
    # O envelope mantém-se AES-256-GCM porque a KEK é sempre 32 bytes
    encrypted_session_key_for_agent = encrypt_with_aes_gcm(
        session_key.encode("utf-8"),
        shared_key
    )

    send_json(conn, {
        "action": "send_encrypted_file",
        "recipient": recipient,
        "filename": file_path.name,
        "cipher": cipher,
        "encrypted_file": encrypted_file,
        "encrypted_session_key_for_agent": encrypted_session_key_for_agent
    })

    response = recv_json(conn)
    print(response["message"])

# assinatura de ficheiro pelo agente (RSA-PSS)
def send_signed_file(conn: socket.socket) -> None:
    recipient = input("Destinatário online: ").strip()
    file_path_str = input("Caminho do ficheiro a assinar e enviar: ").strip()

    file_path = Path(file_path_str)

    if not file_path.exists() or not file_path.is_file():
        print("Ficheiro não encontrado.")
        return

    file_bytes = file_path.read_bytes()

    # Pede ao Mr. Smith para assinar e entregar ao destinatário
    # O servidor é que tem a chave privada de assinatura
    send_json(conn, {
        "action": "send_signed_file",
        "recipient": recipient,
        "filename": file_path.name,
        "file_b64": encode_b64(file_bytes)
    })

    response = recv_json(conn)
    print(response["message"])


def verify_signed_file() -> None:
    # Verifica a assinatura de um ficheiro .json assinado pelo Mr. Smith
    signed_file_path_str = input("Caminho do ficheiro .json assinado: ").strip()
    signed_file_path = Path(signed_file_path_str)

    if not signed_file_path.exists() or not signed_file_path.is_file():
        print("Ficheiro assinado não encontrado.")
        return

    with open(signed_file_path, "r", encoding="utf-8") as file:
        signed_file = json.load(file)

    file_bytes = decode_b64(signed_file["file_b64"])
    signature = signed_file["signature"]
    public_key = decode_b64(signed_file["public_key"])

    valid = verify_signature(file_bytes, signature, public_key)

    if valid:
        print("Assinatura válida: o ficheiro foi assinado pelo Mr. Smith e não foi alterado.")
    else:
        print("Assinatura inválida: o ficheiro ou a assinatura podem ter sido alterados.")

def list_inbox(conn: socket.socket) -> list[dict]:
    # lista de ficheiros pendentes na caixa de entrada do utilizador no servidor
    send_json(conn, {
        "action": "list_inbox"
    })

    response = recv_json(conn)

    if response["status"] != "ok":
        print(response["message"])
        return []

    files = response["files"]

    if not files:
        print("A tua caixa de entrada está vazia.")
        return []

    print("\nFicheiros recebidos:")
    for item in files:
        print(
            f"{item['index']} - {item['filename']} "
            f"de {item['sender']} "
            f"({item['type']})"
        )

    print()
    return files


def download_file(conn: socket.socket, shared_key: str) -> None:
    # Seleciona um ficheiro da inbox e processa-o conforme o seu tipo
    files = list_inbox(conn)

    if not files:
        return

    index_text = input("Número do ficheiro a receber: ").strip()

    if not index_text.isdigit():
        print("Índice inválido.")
        return

    send_json(conn, {
        "action": "download_file",
        "index": int(index_text)
    })

    response = recv_json(conn)

    if response["status"] != "ok":
        print(response["message"])
        return

    file_info = response["file"]

    sender = file_info["sender"]
    filename = file_info["filename"]
    file_type = file_info["type"]

    if file_type == "plain":
        file_bytes = decode_b64(file_info["file_b64"])
        received_hmac = file_info["hmac"]

        valid_hmac = verify_hmac_sha256(
            file_bytes,
            shared_key,
            received_hmac
        )

        safe_filename = f"received_from_{sender}_{filename}"
        output_path = INBOX_DIR / safe_filename
        output_path.write_bytes(file_bytes)

        print(f"\nFicheiro guardado em: {output_path}")

        if valid_hmac:
            print("HMAC válido: o ficheiro chegou íntegro.")
        else:
            print("HMAC inválido: o ficheiro pode ter sido alterado.")

        print()

    elif file_type == "encrypted":
        cipher = file_info.get("cipher", "AES-256-GCM")  # default p/ retro-compat

        try:
            # 1) O destinatário obtém a chave de sessão 
            session_key_bytes = decrypt_with_aes_gcm(
                file_info["encrypted_session_key"],
                shared_key
            )

            session_key = session_key_bytes.decode("utf-8")

            # 2) Decifra o ficheiro com a cifra escolhida pelo emissor
            file_bytes = decrypt_with_cipher(
                file_info["encrypted_file"],
                session_key,
                cipher
            )

        except Exception:
            print("Erro: não foi possível decifrar o ficheiro.")
            return

        safe_filename = f"decrypted_from_{sender}_{filename}"
        output_path = INBOX_DIR / safe_filename
        output_path.write_bytes(file_bytes)

        print(f"\nFicheiro decifrado e guardado em: {output_path}")
        print(f"{cipher} válido: ficheiro decifrado com sucesso e íntegro.")
        print()

    elif file_type == "signed":
        file_bytes = decode_b64(file_info["file_b64"])
        signature = file_info["signature"]
        public_key = decode_b64(file_info["public_key"])

        # Verificação RSA-PSS com a chave pública do Mr. Smith
        # (incluída no ficheiro assinado para verificação offline)
        valid = verify_signature(file_bytes, signature, public_key)

        safe_filename = f"signed_from_{sender}_{filename}"
        output_path = INBOX_DIR / safe_filename
        output_path.write_bytes(file_bytes)

        print(f"\nFicheiro guardado em: {output_path}")

        if valid:
            print("Assinatura válida: ficheiro autenticado pelo Mr. Smith e íntegro.")
        else:
            print("Assinatura inválida: o ficheiro ou a assinatura podem ter sido alterados.")
        print()

    else:
        print("Tipo de ficheiro desconhecido.")


HELP_TEXTS = {
    "1": ("Visão geral do sistema", """
MR.SMITH é uma plataforma de partilha segura de ficheiros com um
servidor que atua como agente de confiança (TTP).

ARQUITETURA
  - O servidor escuta na porta 5000
  - Clientes ligam-se ao servidor
  - Clientes não comunicam diretamente entre si

MODOS DE ENVIO
  - Em claro + HMAC
  - Cifrado (AES-GCM / ChaCha20)
  - Assinado pelo Mr. Smith

EXECUÇÃO
  python3 client.py <IP>
  python3 client_tui.py <IP>
"""),

    "2": ("Registo e autenticação", """
REGISTO
  - Escolhes username e password
  - A password nunca é enviada em claro
  - O cliente envia apenas PBKDF2(password, salt)
  - O servidor gera um seed secreto e envia-o cifrado com RSA-OAEP
  - O seed fica guardado localmente cifrado com AES-GCM

LOGIN
  - Usa desafio-resposta com HMAC
  - O servidor envia um nonce aleatório
  - O cliente responde com HMAC(nonce, password_hash)
  - Cliente e servidor derivam a mesma KEK de sessão
"""),

    "3": ("Enviar ficheiros", """
1) EM CLARO + HMAC
   - O ficheiro não é cifrado
   - HMAC garante integridade

2) CIFRADO
   - AES-128/192/256-GCM ou ChaCha20-Poly1305
   - Cada ficheiro usa uma chave de sessão diferente
   - A chave de sessão é protegida com a KEK da sessão

3) ASSINADO
   - O Mr. Smith assina com RSA-PSS
   - O destinatário verifica com a chave pública do agente
"""),

    "4": ("Receber ficheiros", """
INBOX
  - Lista ficheiros pendentes no servidor
  - Cada ficheiro pode ser:
      plain
      encrypted
      signed

VERIFICAÇÕES
  plain     -> verifica HMAC
  encrypted -> decifra chave de sessão e ficheiro
  signed    -> verifica assinatura RSA-PSS

Os ficheiros recebidos ficam guardados na pasta inbox/.
"""),

    "5": ("Conceitos criptográficos usados", """
PBKDF2-HMAC-SHA256
  - Proteção de passwords

HMAC-SHA256
  - Integridade e autenticação

AES-GCM / ChaCha20-Poly1305
  - Confidencialidade + integridade

RSA-OAEP
  - Troca segura do seed

RSA-PSS
  - Assinaturas digitais

KEK DE SESSÃO
  - Derivada de HMAC(seed, counter)
  - Muda a cada login
"""),

    "6": ("Limitações e pressupostos", """
PRESSUPOSTOS
  - O servidor é considerado confiável
  - O atacante pode escutar a rede

LIMITAÇÕES
  - O modo plain não garante confidencialidade
  - O sistema não protege contra malware/keyloggers
  - O servidor consegue ver metadata (quem comunica com quem)
"""),
}

def help_menu() -> None:
    # Mostrar o menu de ajuda detalhada com tópicos explicativos
    while True:
        print("\n=== AJUDA MR.SMITH ===")
        for key in HELP_TEXTS:
            title = HELP_TEXTS[key][0]
            print(f"  {key} - {title}")
        print("  0 - Voltar")

        option = input("\nOpção: ").strip()

        if option == "0":
            return

        if option in HELP_TEXTS:
            print(HELP_TEXTS[option][1])
            input("[Enter para voltar ao menu de ajuda]")
        else:
            print("Opção inválida.")


def send_menu(conn: socket.socket, shared_key: str) -> None:
    # Menu de escolha do modo de envio de ficheiro
    print("\n=== Enviar ficheiro ===")
    print("Modo:")
    print("  1 - Em claro com HMAC (integridade)")
    print("  2 - Cifrado com AES-GCM / ChaCha20 (confidencialidade + integridade)")
    print("  3 - Assinado pelo Mr. Smith (autenticidade)")
    print("  0 - Voltar")

    option = input("Opção: ").strip()

    if option == "1":
        send_plain_file(conn, shared_key)
    elif option == "2":
        send_encrypted_file(conn, shared_key)
    elif option == "3":
        send_signed_file(conn)
    elif option == "0":
        return
    else:
        print("Opção inválida.")


def authenticated_menu(conn: socket.socket, username: str, shared_key: str) -> None:
    # Menu exibido após login bem-sucedido, para operações autenticadas
    while True:
        print("\n=== MR.SMITH | Cliente autenticado ===")
        print(f"Utilizador: {username}")
        print("1 - Ver utilizadores online")
        print("2 - Enviar ficheiro")
        print("3 - Ver/receber ficheiros da inbox")
        print("4 - Verificar ficheiro assinado (.json local)")
        print("5 - Ajuda")
        print("6 - Sair")

        option = input("Opção: ").strip()

        if option == "1":
            list_online(conn)

        elif option == "2":
            send_menu(conn, shared_key)

        elif option == "3":
            download_file(conn, shared_key)

        elif option == "4":
            verify_signed_file()

        elif option == "5":
            help_menu()

        elif option == "6":
            send_json(conn, {"action": "logout"})
            response = recv_json(conn)
            print(response["message"])
            break

        else:
            print("Opção inválida.")

def main() -> None:
    # Conecta ao servidor e apresenta o menu principal de registo/login
    # A ligação TCP permanece aberta durante toda a execução
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((HOST, PORT))

        while True:
            print("\n=== MR.SMITH ===")
            print("1 - Registar")
            print("2 - Login")
            print("3 - Ajuda")
            print("4 - Sair")

            option = input("Opção: ").strip()

            if option == "1":
                register(conn)

            elif option == "2":
                username, shared_key = login(conn)

                if username is not None:
                    authenticated_menu(conn, username, shared_key)

            elif option == "3":
                help_menu()

            elif option == "4":
                print("Até já.")
                break

            else:
                print("Opção inválida.")


if __name__ == "__main__":
    main()
