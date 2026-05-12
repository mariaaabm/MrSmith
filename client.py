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

# IP do servidor: pode ser passado como argumento (ex.: python3 client.py 192.168.1.50).
# Default: localhost.
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = 5000

INBOX_DIR = Path("inbox")
SENT_DIR = Path("sent")
KEYS_DIR = Path("client_keys")

INBOX_DIR.mkdir(exist_ok=True)
SENT_DIR.mkdir(exist_ok=True)
KEYS_DIR.mkdir(exist_ok=True)


def save_local_seed(username: str, password: str, seed_b64: str) -> None:
    """
    Persiste o seed em disco, cifrado com uma chave derivada da password.
    O seed é o segredo de longa duração; só este cliente o conhece em claro.
    """
    salt_b64, derived_key_b64 = hash_password(password)
    blob = encrypt_with_aes_gcm(seed_b64.encode("utf-8"), derived_key_b64)

    seed_file = KEYS_DIR / f"{username}.seed"
    with open(seed_file, "w", encoding="utf-8") as file:
        json.dump({"salt": salt_b64, "blob": blob}, file, indent=4)


def load_local_seed(username: str, password: str) -> str:
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
    message = json.dumps(data).encode("utf-8")
    conn.sendall(len(message).to_bytes(4, "big") + message)


def recv_json(conn: socket.socket) -> dict | None:
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


def register(conn: socket.socket) -> None:
    username = input("Username: ").strip()
    password = getpass("Password: ")

    # 1) PBKDF2 corre LOCALMENTE — a password nunca sai daqui.
    salt_b64, password_hash_b64 = hash_password(password)

    # 2) Par RSA-2048 efémero — a privada fica neste cliente, a pública vai.
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

    # 3) Decifra o seed (RSA-OAEP) e persiste-o localmente
    #    cifrado com chave derivada da password.
    seed_bytes = decrypt_with_rsa_oaep(
        response["encrypted_seed"],
        private_pem
    )
    seed_b64 = seed_bytes.decode("utf-8")

    save_local_seed(username, password, seed_b64)

    print("\nSeed estabelecido em segurança com o Mr. Smith.")
    print("(Recebido via RSA-OAEP, guardado localmente cifrado com a tua password.)")
    print()


def login(conn: socket.socket) -> tuple[str | None, str | None]:
    username = input("Username: ").strip()
    password = getpass("Password: ")

    # Fase 1: anunciar quem somos e receber salt + desafio.
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
    # e provar conhecimento dela calculando HMAC(nonce, pwd_hash).
    # A password nunca sai daqui.
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

    # Carrega o seed local (cifrado com a password) e deriva a KEK desta
    # sessão. O servidor faz a mesma derivação independentemente —
    # nada relativo à KEK viaja na rede.
    try:
        seed_b64 = load_local_seed(username, password)
    except FileNotFoundError as error:
        print(f"Erro: {error}")
        return None, None

    counter = response["login_counter"]
    kek_session = derive_session_kek(seed_b64, counter)

    return username, kek_session


def list_online(conn: socket.socket) -> None:
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


def send_plain_file(conn: socket.socket, shared_key: str) -> None:
    recipient = input("Destinatário online: ").strip()
    file_path_str = input("Caminho do ficheiro a enviar: ").strip()

    file_path = Path(file_path_str)

    if not file_path.exists() or not file_path.is_file():
        print("Ficheiro não encontrado.")
        return

    file_bytes = file_path.read_bytes()

    # HMAC calculado sobre o conteúdo do ficheiro.
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


def send_encrypted_file(conn: socket.socket, shared_key: str) -> None:
    recipient = input("Destinatário online: ").strip()
    file_path_str = input("Caminho do ficheiro a enviar: ").strip()

    file_path = Path(file_path_str)

    if not file_path.exists() or not file_path.is_file():
        print("Ficheiro não encontrado.")
        return

    file_bytes = file_path.read_bytes()

    # Escolha de cifra e tamanho de chave (ponto 4 dos fortalecimentos).
    cipher = choose_cipher()
    key_size = SUPPORTED_CIPHERS[cipher]

    # Chave de sessão: gerada pelo cliente emissor com o tamanho exigido
    # pela cifra escolhida (16/24/32 bytes).
    session_key = generate_symmetric_key(size_bytes=key_size)

    # Ficheiro cifrado com a chave de sessão usando a cifra escolhida.
    encrypted_file = encrypt_with_cipher(file_bytes, session_key, cipher)

    # Chave de sessão protegida para o agente.
    # O envelope mantém-se AES-256-GCM porque a KEK é sempre 32 bytes.
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

def send_signed_file(conn: socket.socket) -> None:
    recipient = input("Destinatário online: ").strip()
    file_path_str = input("Caminho do ficheiro a assinar e enviar: ").strip()

    file_path = Path(file_path_str)

    if not file_path.exists() or not file_path.is_file():
        print("Ficheiro não encontrado.")
        return

    file_bytes = file_path.read_bytes()

    # Pede ao Mr. Smith para assinar e entregar ao destinatário.
    # O servidor é que detém a chave privada de assinatura.
    send_json(conn, {
        "action": "send_signed_file",
        "recipient": recipient,
        "filename": file_path.name,
        "file_b64": encode_b64(file_bytes)
    })

    response = recv_json(conn)
    print(response["message"])


def verify_signed_file() -> None:
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
            # 1) O destinatário obtém a chave de sessão (envelope sempre AES-256-GCM).
            session_key_bytes = decrypt_with_aes_gcm(
                file_info["encrypted_session_key"],
                shared_key
            )

            session_key = session_key_bytes.decode("utf-8")

            # 2) Decifra o ficheiro com a cifra escolhida pelo emissor.
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
        # (incluída no ficheiro assinado para verificação offline).
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
MR.SMITH é uma plataforma de partilha segura de ficheiros entre utilizadores,
com um servidor que atua como agente de confiança (TTP - Trusted Third Party).

ARQUITETURA
  - Servidor TTP escuta na porta 5000 (em todas as interfaces)
  - Clientes ligam-se ao servidor para comunicar entre si
  - Os clientes NÃO falam diretamente uns com os outros

EXECUÇÃO EM REDE
  - Por defeito, o cliente liga-se a 127.0.0.1 (mesma máquina do servidor)
  - Para ligar a um servidor noutra máquina:
      python3 client.py <IP_DO_SERVIDOR>
      python3 client_tui.py <IP_DO_SERVIDOR>
  - O servidor mostra o seu IP de rede ao arrancar.

3 MODOS DE ENVIO
  - Em claro + HMAC      -> integridade (sem confidencialidade)
  - Cifrado AES-256-GCM  -> confidencialidade + integridade
  - Assinado pelo agente -> autenticidade certificada (RSA-PSS)

PRESSUPOSTO
  O servidor é confiável (não consulta nem altera dados maliciosamente).
  Os atacantes podem escutar/manipular a rede, mas não comprometer o agente.
"""),

    "2": ("Registo e autenticação", """
REGISTO (uma vez por computador)
  - Escolhes username único e password.
  - A password NUNCA viaja pela rede:
      O cliente computa LOCALMENTE: hash = PBKDF2-SHA256(password, salt, 200k)
      Só (salt, hash) são enviados ao servidor.
  - O servidor gera um seed aleatório (256 bits) e envia-o cifrado com RSA-OAEP,
    usando uma chave pública efémera gerada pelo cliente no momento.
  - O cliente decifra o seed e guarda-o em client_keys/<user>.seed,
    ele próprio cifrado com chave derivada da password.

LOGIN (a cada sessão)
  - Desafio-resposta com HMAC, sem transmitir a password:
      1. Cliente: "sou alice"
      2. Servidor: devolve (salt, nonce aleatório)
      3. Cliente: prova = HMAC(nonce, PBKDF2(password, salt))
      4. Servidor: verifica e devolve apenas um contador de login
  - O nonce é diferente a cada login -> anti-replay.
  - Ambos derivam KEK_sessao = HMAC(seed, login_counter).
  - O contador incrementa a cada login -> KEK diferente por sessão (rotação).
"""),

    "3": ("Enviar ficheiros (3 modos)", """
1) EM CLARO + HMAC
   - Ficheiro vai em base64, sem cifrar.
   - Acompanhado de HMAC-SHA256(ficheiro, KEK_alice_sessao).
   - Agente verifica HMAC com KEK da Alice, regera com KEK do Bob, encaminha.
   - Garante INTEGRIDADE: destinatário sabe que o ficheiro não foi alterado.
   - NÃO garante confidencialidade: quem escuta a rede vê o conteúdo.

2) CIFRADO (CIFRA E TAMANHO À ESCOLHA)
   - O emissor escolhe a cifra:
       AES-128-GCM / AES-192-GCM / AES-256-GCM / ChaCha20-Poly1305
   - Cliente gera chave de sessão única só para este ficheiro, do tamanho
     exigido pela cifra escolhida (16/24/32 bytes).
   - Cifra o ficheiro com essa chave (nonce de 96 bits único).
   - Cifra a chave de sessão com a KEK da Alice (envelope encryption,
     sempre AES-256-GCM porque a KEK é de 32 bytes).
   - Agente decifra o envelope com KEK_alice, re-cifra com KEK_bob, encaminha.
   - O ficheiro cifrado NUNCA é decifrado pelo agente — só a chave que o protege.
   - Garante CONFIDENCIALIDADE + INTEGRIDADE (todas as cifras são AEAD).

3) ASSINADO PELO MR. SMITH
   - Cliente envia o ficheiro em claro.
   - Agente assina com a sua chave privada RSA-2048 (PSS + SHA-256).
   - Entrega ao destinatário: ficheiro + assinatura + chave pública do agente.
   - Garante AUTENTICIDADE: destinatário verifica que o agente assinou
     (e portanto que o ficheiro veio de um utilizador autenticado).
"""),

    "4": ("Receber ficheiros (inbox)", """
Opção 3 do menu principal: "Ver/receber ficheiros da inbox".

FLUXO
  - Mostra a lista de ficheiros pendentes para ti no servidor.
  - Cada ficheiro tem um tipo: plain / encrypted / signed.
  - Escolhes o ficheiro pelo número.
  - O cliente verifica e/ou decifra automaticamente conforme o tipo:
      plain     -> verifica HMAC com a KEK desta sessão
      encrypted -> decifra envelope da chave -> decifra ficheiro com AES-GCM
      signed    -> verifica assinatura RSA-PSS com a chave pública incluída
  - Ficheiro guardado em inbox/<tipo>_from_<remetente>_<nome>

NOTA
  Se a verificação falhar (HMAC inválido ou assinatura inválida),
  o ficheiro continua a ser guardado mas és avisada que pode ter sido alterado.
"""),

    "5": ("Verificar ficheiro assinado (.json local)", """
Opção 4 do menu principal: verificação OFFLINE de uma assinatura.

PARA QUE SERVE
  Permite-te verificar que um ficheiro .json assinado pelo Mr.Smith é
  autêntico, mesmo sem estares ligada ao servidor.

QUANDO É ÚTIL
  - Recebes um ficheiro assinado por outro canal (email, USB...)
  - Queres confirmar que uma assinatura armazenada há semanas continua válida
  - Queres demonstrar a alguém que não confia que o agente assinou

COMO FUNCIONA
  - Indicas o caminho do ficheiro .json
  - O cliente lê (ficheiro, assinatura, chave pública)
  - Verifica a assinatura RSA-PSS
  - Diz-te "válida" ou "inválida"
"""),

    "6": ("Conceitos criptográficos usados", """
PBKDF2-HMAC-SHA256 (200 000 iterações)
  Deriva uma chave a partir de password + salt. As iterações tornam
  ataques de dicionário 200000x mais lentos.
  USADO EM: hash de password no servidor, derivação para cifrar seed local.

HMAC-SHA256
  MAC (Message Authentication Code) baseado em hash com chave secreta.
  Garante integridade + autenticidade — só quem tem a chave produz um MAC válido.
  USADO EM: envio em claro, desafio-resposta no login, derivação da KEK de sessão.

AES-256-GCM
  Cifra simétrica autenticada (Encrypt-then-MAC integrado).
  Chave 256 bits, nonce 96 bits ÚNICO por cifragem.
  Garante confidencialidade + integridade numa só operação.
  USADO EM: cifra de ficheiros, envelope da chave de sessão, cifra do seed local.

RSA-OAEP (Optimal Asymmetric Encryption Padding)
  Cifra de chave pública RSA-2048 com padding probabilístico (MGF1+SHA-256).
  Prova de segurança no modelo CCA.
  USADO EM: troca do seed no momento do registo.

RSA-PSS (Probabilistic Signature Scheme)
  Assinatura digital RSA-2048 com padding probabilístico (MGF1+SHA-256).
  Cada assinatura é diferente mesmo da mesma mensagem.
  USADO EM: assinatura do agente sobre ficheiros enviados.

SEED
  Segredo de longa duração estabelecido no registo.
  Conhecido apenas pelo cliente (localmente) e pelo servidor.
  Nunca é transmitido em claro.

KEK DE SESSÃO
  Derivada de HMAC(seed, login_counter).
  Muda a cada login (rotação).
  Usada para HMACs e envelopes durante a sessão atual.
"""),

    "7": ("Onde estão as minhas chaves e dados", """
NO SERVIDOR (users.json)
  - salt (público)
  - password_hash (PBKDF2 da tua password)
  - seed (segredo de longa duração)
  - login_counter (incrementa a cada login)
  NUNCA: a tua password em claro.

NO CLIENTE (client_keys/<user>.seed)
  - salt local (público)
  - blob: seed cifrado com AES-GCM, chave = PBKDF2(password, salt local)
  NUNCA: password, seed em claro.

NO SERVIDOR (keys/mrsmith_*.pem)
  - Par RSA-2048 do agente para assinaturas digitais.
  - Gerado uma vez ao arranque, persistente entre reinícios.

PASTAS DE FICHEIROS
  - sent/        -> ficheiros que TU envias (origem)
  - inbox/       -> ficheiros que recebes (destino)
  - client_keys/ -> seed local cifrado de cada utilizador deste computador
  - keys/        -> par de chaves RSA do agente (no servidor)
"""),

    "8": ("Modelo de segurança e ameaças", """
O QUE ESTÁ PROTEGIDO

  CONFIDENCIALIDADE DA PASSWORD
    - Nunca sai do cliente em claro.
    - Servidor só vê o hash PBKDF2.
    - Sniffing da rede não revela.

  CONFIDENCIALIDADE DO SEED
    - Trocado no registo via RSA-OAEP — sniffing inútil.
    - Em disco no cliente: cifrado com chave derivada da password.

  CONFIDENCIALIDADE DOS FICHEIROS (modo cifrado)
    - AES-256-GCM com chave de sessão única por ficheiro.
    - Envelope da chave: AES-GCM com KEK da sessão.
    - Servidor decifra apenas o envelope, nunca o ficheiro.

  INTEGRIDADE
    - HMAC nos envios sem cifra; tag GCM nos cifrados; PSS nas assinaturas.

  AUTENTICIDADE
    - Login: desafio-resposta com HMAC (anti-replay via nonce).
    - Mensagens: HMAC ou assinatura RSA-PSS.

  FRESCURA
    - Rotação de KEK a cada login (HMAC(seed, counter)).
    - Nonce diferente em cada AES-GCM e em cada desafio de login.


O QUE NÃO ESTÁ PROTEGIDO

  - Comprometimento do servidor: atacante obtém todas as seeds.
    Mitigação: assume-se TTP confiável.
  - Ataques físicos ao cliente (keylogger, RAM dump).
  - Denial of Service: não há limites de rate.
  - Análise de tráfego: o atacante vê quem comunica com quem (metadata).
"""),
}


def help_menu() -> None:
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
    print("\n=== Enviar ficheiro ===")
    print("Modo:")
    print("  1 - Em claro com HMAC (integridade)")
    print("  2 - Cifrado com AES-GCM (confidencialidade + integridade)")
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