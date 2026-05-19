import json
import socket
import threading
from pathlib import Path

import hmac as hmac_module

# MrSmith servidor de confiança
# O servidor aceita conexões TCP de clientes, gere utilizadores,
# valida logins, troca mensagens seguras e armazena ficheiros temporários

from crypto_utils import (
    hash_password,
    generate_symmetric_key,
    create_hmac_sha256,
    verify_hmac_sha256,
    decode_b64,
    encode_b64,
    encrypt_with_aes_gcm,
    decrypt_with_aes_gcm,
    generate_rsa_key_pair,
    sign_data,
    random_bytes,
    encrypt_with_rsa_oaep,
    derive_session_kek,
)

# 0.0.0.0 -> aceita ligações de qualquer interface (localhost + rede)
# Para restringir a localhost apenas, mudar para "127.0.0.1"
HOST = "0.0.0.0"
PORT = 5000

USERS_FILE = Path("users.json")
KEYS_DIR = Path("keys")
MRSMITH_PRIVATE_KEY_FILE = KEYS_DIR / "mrsmith_private_key.pem"
MRSMITH_PUBLIC_KEY_FILE = KEYS_DIR / "mrsmith_public_key.pem"

online_users = {}
online_users_lock = threading.Lock()

# Mensagens/ficheiros guardados temporariamente no servidor
# Estrutura:
# {
#   "bob": [
#       {
#           "sender": "alice",
#           "filename": "teste.txt",
#           "file_b64": "...",
#           "hmac": "...",
#           "type": "plain"
#       }
#   ]
# }
pending_files = {}
pending_files_lock = threading.Lock()


def load_users() -> dict:
    # Carrega os utilizadores armazenados em JSON
    # Se o ficheiro ainda não existir, cria um novo ficheiro vazio
    if not USERS_FILE.exists():
        USERS_FILE.write_text("{}", encoding="utf-8")

    with open(USERS_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def save_users(users: dict) -> None:
    # guarda novamente os utilizadores no ficheiro JSON
    with open(USERS_FILE, "w", encoding="utf-8") as file:
        json.dump(users, file, indent=4)

def setup_mrsmith_keys() -> None:
    # Garante que existe um par de chaves RSA para o agente Mr. Smith.
    KEYS_DIR.mkdir(exist_ok=True)

    if MRSMITH_PRIVATE_KEY_FILE.exists() and MRSMITH_PUBLIC_KEY_FILE.exists():
        return

    private_pem, public_pem = generate_rsa_key_pair()

    MRSMITH_PRIVATE_KEY_FILE.write_bytes(private_pem)
    MRSMITH_PUBLIC_KEY_FILE.write_bytes(public_pem)

    print("[MR.SMITH] Par de chaves RSA criado.")


def load_mrsmith_private_key() -> bytes:
    # Carrega a chave privada do agente Mr. Smith.
    return MRSMITH_PRIVATE_KEY_FILE.read_bytes()


def load_mrsmith_public_key() -> bytes:
    # Carrega a chave pública do agente Mr. Smith.
    return MRSMITH_PUBLIC_KEY_FILE.read_bytes()

def send_json(conn: socket.socket, data: dict) -> None:
    # Envia um dicionário codificado em JSON com prefixo do tamanho da mensagem.
    message = json.dumps(data).encode("utf-8")
    conn.sendall(len(message).to_bytes(4, "big") + message)


def recv_json(conn: socket.socket) -> dict | None:
    # Recebe um pacote JSON com prefixo de 4 bytes de tamanho.
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


def register_user(username: str, salt_b64: str, password_hash_b64: str,
                  public_key_pem: bytes) -> dict:
    # Regista um novo utilizador
    users = load_users()

    # Verifica se o nome de utilizador já existe 
    if username in users:
        return {
            "status": "error",
            "message": "Esse utilizador já existe."
        }

    seed = generate_symmetric_key()

    users[username] = {
        "salt": salt_b64,
        "password_hash": password_hash_b64,
        "seed": seed,
        "login_counter": 0
    }

    save_users(users)

    encrypted_seed = encrypt_with_rsa_oaep(
        seed.encode("utf-8"),
        public_key_pem
    )

    return {
        "status": "ok",
        "message": "Registo feito com sucesso.",
        "encrypted_seed": encrypted_seed
    }


def login_init(username: str) -> tuple[dict, bytes | None]:
    
    # Primeira fase do login. Verifica se o utilizador existe e devolve o salt e um nonce
    users = load_users()

    if username not in users:
        return {
            "status": "error",
            "message": "Utilizador não encontrado."
        }, None

    user = users[username]
    nonce = random_bytes(32)

    return {
        "status": "ok",
        "salt": user["salt"],
        "nonce": encode_b64(nonce)
    }, nonce


def login_proof(username: str, proof_b64: str,
                nonce: bytes, conn: socket.socket) -> dict:
   
    # Segunda fase do login. Verifica o HMAC enviado pelo cliente e, se válido,
    # marca o utilizador como online e guarda a KEK de sessão
    users = load_users()

    if username not in users:
        return {
            "status": "error",
            "message": "Utilizador não encontrado."
        }

    user = users[username]
    expected_proof_b64 = create_hmac_sha256(nonce, user["password_hash"])

    if not hmac_module.compare_digest(proof_b64, expected_proof_b64):
        return {
            "status": "error",
            "message": "Credenciais inválidas."
        }

    user["login_counter"] = user.get("login_counter", 0) + 1
    new_counter = user["login_counter"]
    save_users(users)

    kek_session = derive_session_kek(user["seed"], new_counter)

    with online_users_lock:
        online_users[username] = {"conn": conn, "kek": kek_session}

    return {
        "status": "ok",
        "message": "Login feito com sucesso.",
        "login_counter": new_counter
    }


def get_online_users(current_username: str) -> list[str]:
    # Retorna a lista de utilizadores online, excluindo o próprio
    with online_users_lock:
        return [
            username
            for username in online_users.keys()
            if username != current_username
        ]


def send_plain_file(sender: str, request: dict) -> dict:
    # Recebe um ficheiro "plain" enviado de um utilizador para outro
    # O servidor valida o HMAC com a KEK do emissor e depois re-marca
    # o ficheiro com o HMAC da KEK do destinatário
    users = load_users()

    recipient = request.get("recipient")
    filename = request.get("filename")
    file_b64 = request.get("file_b64")
    sender_hmac = request.get("hmac")

    if recipient not in users:
        return {
            "status": "error",
            "message": "O destinatário não existe."
        }

    with online_users_lock:
        if recipient not in online_users:
            return {
                "status": "error",
                "message": "O destinatário não está online."
            }
        # KEKs de sessão (derivadas no login)
        sender_kek = online_users[sender]["kek"]
        recipient_kek = online_users[recipient]["kek"]

    file_bytes = decode_b64(file_b64)

    # 1) O agente verifica se o ficheiro recebido do emissor está íntegro
    valid_sender_hmac = verify_hmac_sha256(
        file_bytes,
        sender_kek,
        sender_hmac
    )

    if not valid_sender_hmac:
        return {
            "status": "error",
            "message": "HMAC inválido. O ficheiro pode ter sido alterado."
        }

    # 2) O agente cria um novo HMAC com a KEK de sessão do destinatário
    recipient_hmac = create_hmac_sha256(file_bytes, recipient_kek)

    message = {
        "type": "plain",
        "sender": sender,
        "filename": filename,
        "file_b64": file_b64,
        "hmac": recipient_hmac
    }

    with pending_files_lock:
        if recipient not in pending_files:
            pending_files[recipient] = []

        pending_files[recipient].append(message)

    return {
        "status": "ok",
        "message": f"Ficheiro '{filename}' enviado para {recipient} com HMAC válido."
    }

def send_encrypted_file(sender: str, request: dict) -> dict:
    # Recebe um ficheiro cifrado e reencapsula a chave de sessão
    # cifrada com a KEK do destinatário
    users = load_users()

    recipient = request.get("recipient")
    filename = request.get("filename")
    encrypted_file = request.get("encrypted_file")
    encrypted_session_key_for_agent = request.get("encrypted_session_key_for_agent")
    cipher = request.get("cipher", "AES-256-GCM")  # por defeito

    if recipient not in users:
        return {
            "status": "error",
            "message": "O destinatário não existe."
        }

    with online_users_lock:
        if recipient not in online_users:
            return {
                "status": "error",
                "message": "O destinatário não está online."
            }
        sender_kek = online_users[sender]["kek"]
        recipient_kek = online_users[recipient]["kek"]

    try:
        # 1) O agente obtém a chave de sessão enviada pelo emissor
        session_key_bytes = decrypt_with_aes_gcm(
            encrypted_session_key_for_agent,
            sender_kek
        )

        session_key_b64 = session_key_bytes.decode("utf-8")

        # 2) O agente volta a proteger a mesma chave de sessão para o destinatário
        encrypted_session_key_for_recipient = encrypt_with_aes_gcm(
            session_key_b64.encode("utf-8"),
            recipient_kek
        )

    except Exception:
        return {
            "status": "error",
            "message": "Não foi possível validar/proteger a chave de sessão."
        }

    message = {
        "type": "encrypted",
        "sender": sender,
        "filename": filename,
        "cipher": cipher,
        "encrypted_file": encrypted_file,
        "encrypted_session_key": encrypted_session_key_for_recipient
    }

    with pending_files_lock:
        if recipient not in pending_files:
            pending_files[recipient] = []

        pending_files[recipient].append(message)

    return {
        "status": "ok",
        "message": f"Ficheiro '{filename}' cifrado ({cipher}) e enviado para {recipient}."
    }


def send_signed_file(sender: str, request: dict) -> dict:
    # Recebe um ficheiro que será assinado pelo agente Mr. Smith
    users = load_users()

    recipient = request.get("recipient")
    filename = request.get("filename")
    file_b64 = request.get("file_b64")

    if recipient not in users:
        return {
            "status": "error",
            "message": "O destinatário não existe."
        }

    with online_users_lock:
        if recipient not in online_users:
            return {
                "status": "error",
                "message": "O destinatário não está online."
            }

    file_bytes = decode_b64(file_b64)
    private_key = load_mrsmith_private_key()
    public_key = load_mrsmith_public_key()

    # O agente assina o ficheiro com a sua chave privada RSA
    # Inclui a sua chave pública para que o destinatário possa verificar
    signature = sign_data(file_bytes, private_key)

    message = {
        "type": "signed",
        "sender": sender,
        "filename": filename,
        "file_b64": file_b64,
        "signature": signature,
        "public_key": encode_b64(public_key)
    }

    with pending_files_lock:
        if recipient not in pending_files:
            pending_files[recipient] = []
        pending_files[recipient].append(message)

    return {
        "status": "ok",
        "message": f"Ficheiro '{filename}' assinado pelo Mr. Smith e enviado para {recipient}."
    }

def list_inbox(username: str) -> dict:
    # Lista os ficheiros pendentes para um utilizador
    with pending_files_lock:
        files = pending_files.get(username, [])

        summaries = []
        for index, item in enumerate(files):
            summaries.append({
                "index": index,
                "sender": item["sender"],
                "filename": item["filename"],
                "type": item["type"]
            })

    return {
        "status": "ok",
        "files": summaries
    }


def download_file(username: str, index: int) -> dict:
    # Devolve o ficheiro selecionado e remove-o da caixa de entrada
    with pending_files_lock:
        files = pending_files.get(username, [])

        if index < 0 or index >= len(files):
            return {
                "status": "error",
                "message": "Índice inválido."
            }

        item = files.pop(index)

    return {
        "status": "ok",
        "file": item
    }


def handle_client(conn: socket.socket, addr) -> None:
    # Lida com um cliente ligado numa thread separada
    # Gerencia registo, login, envios de ficheiros e consulta de inbox
    print(f"[+] Cliente ligado: {addr}")

    logged_username = None

    pending_login_user: str | None = None
    pending_login_nonce: bytes | None = None

    try:
        while True:
            request = recv_json(conn)

            if request is None:
                break

            action = request.get("action")

            # registo
            if action == "register":
                response = register_user(
                    request["username"],
                    request["salt"],
                    request["password_hash"],
                    decode_b64(request["public_key_pem"])
                )
                send_json(conn, response)

            # login
            elif action == "login_init":
                response, nonce = login_init(request["username"])

                if response["status"] == "ok":
                    pending_login_user = request["username"]
                    pending_login_nonce = nonce
                else:
                    pending_login_user = None
                    pending_login_nonce = None

                send_json(conn, response)

            # verificar login 
            elif action == "login_proof":
                if pending_login_nonce is None or pending_login_user != request.get("username"):
                    send_json(conn, {
                        "status": "error",
                        "message": "Tens de iniciar o login primeiro."
                    })
                else:
                    response = login_proof(
                        pending_login_user,
                        request["proof"],
                        pending_login_nonce,
                        conn
                    )

                    if response["status"] == "ok":
                        logged_username = pending_login_user

                    # Nonce só pode ser usado uma vez.
                    pending_login_user = None
                    pending_login_nonce = None

                    send_json(conn, response)


            elif action == "list_online":
                if logged_username is None:
                    send_json(conn, {
                        "status": "error",
                        "message": "Tens de fazer login primeiro."
                    })
                else:
                    send_json(conn, {
                        "status": "ok",
                        "users": get_online_users(logged_username)
                    })

            # enviar ficheiros
            elif action == "send_plain_file":
                if logged_username is None:
                    send_json(conn, {
                        "status": "error",
                        "message": "Tens de fazer login primeiro."
                    })
                else:
                    response = send_plain_file(logged_username, request)
                    send_json(conn, response)
            
            # enviar ficheiros cifrados
            elif action == "send_encrypted_file":
                if logged_username is None:
                    send_json(conn, {
                        "status": "error",
                        "message": "Tens de fazer login primeiro."
                    })
                else:
                    response = send_encrypted_file(logged_username, request)
                    send_json(conn, response)
            
            # enviar ficheiros assinados
            elif action == "send_signed_file":
                if logged_username is None:
                    send_json(conn, {
                        "status": "error",
                        "message": "Tens de fazer login primeiro."
                    })
                else:
                    response = send_signed_file(logged_username, request)
                    send_json(conn, response)

            # listar caixa de entrada
            elif action == "list_inbox":
                if logged_username is None:
                    send_json(conn, {
                        "status": "error",
                        "message": "Tens de fazer login primeiro."
                    })
                else:
                    response = list_inbox(logged_username)
                    send_json(conn, response)

            # descarregar ficheiro
            elif action == "download_file":
                if logged_username is None:
                    send_json(conn, {
                        "status": "error",
                        "message": "Tens de fazer login primeiro."
                    })
                else:
                    response = download_file(
                        logged_username,
                        int(request["index"])
                    )
                    send_json(conn, response)

            # logout (terminar sessão, mas não fecha a ligação TCP para permitir novo login)
            elif action == "logout":
                # Limpa apenas o estado da sessão
                if logged_username is not None:
                    with online_users_lock:
                        online_users.pop(logged_username, None)
                    logged_username = None

                send_json(conn, {
                    "status": "ok",
                    "message": "Sessão terminada."
                })

            else:
                send_json(conn, {
                    "status": "error",
                    "message": "Ação desconhecida."
                })

    except Exception as error:
        print(f"[!] Erro com cliente {addr}: {error}")

    finally:
        if logged_username is not None:
            with online_users_lock:
                online_users.pop(logged_username, None)

        conn.close()
        print(f"[-] Cliente desligado: {addr}")


def main() -> None:
    # Inicializa o servidor
    print("[MR.SMITH] Agente de confiança a iniciar...")
    setup_mrsmith_keys() # Garante que as chaves do agente estão criadas

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # liga à porta
        server.bind((HOST, PORT))
        server.listen()

        print(f"[MR.SMITH] A escutar em {HOST}:{PORT}")
        # Mostra o IP da máquina para facilitar a configuração nos clientes remotos
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.connect(("8.8.8.8", 80))
                local_ip = probe.getsockname()[0]
            print(f"[MR.SMITH] IP desta máquina na rede: {local_ip}")
            print(f"[MR.SMITH] Clientes em rede devem ligar com: python3 client_tui.py {local_ip}")
        except Exception:
            print("[MR.SMITH] (não consegui detectar o IP da rede automaticamente)")

        while True:
            conn, addr = server.accept() # Aceita uma nova ligação de cliente
            thread = threading.Thread( # para cada cliente cria uma thread separada
                target=handle_client,
                args=(conn, addr),
                daemon=True
            )
            thread.start()


if __name__ == "__main__":
    main()
