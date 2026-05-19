# Funções criptográficas usadas pelo cliente e pelo servidor
# Fornece funções de hashing de senha, cifragem autenticada, HMAC, RSA e derivação de chaves de sessão
import os
import base64
import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

def random_bytes(size: int) -> bytes:
    # Gera bytes aleatórios seguros usados em chaves, nonces e salts
    return os.urandom(size)


def encode_b64(data: bytes) -> str:
    # converte bytes para texto Base64
    return base64.b64encode(data).decode("utf-8")


def decode_b64(data: str) -> bytes:
    # converte texto Base64 de volta para bytes
    return base64.b64decode(data.encode("utf-8"))


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    # Calcula um hash de password seguro usando PBKDF2-HMAC-SHA256
    # Retorna salt e hash codificados em Base64
    if salt is None:
        salt = os.urandom(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000
    )

    return encode_b64(salt), encode_b64(password_hash)


def verify_password(password: str, salt_b64: str, expected_hash_b64: str) -> bool:
    # Verifica a password comparando hashes 
    salt = decode_b64(salt_b64)
    expected_hash = decode_b64(expected_hash_b64)

    _, password_hash_b64 = hash_password(password, salt)
    password_hash = decode_b64(password_hash_b64)

    return hmac.compare_digest(password_hash, expected_hash)


# Cifras autenticadas suportadas e respetivo tamanho de chave (bytes)
SUPPORTED_CIPHERS = {
    "AES-128-GCM": 16,
    "AES-192-GCM": 24,
    "AES-256-GCM": 32,
    "ChaCha20-Poly1305": 32,
}


def generate_symmetric_key(size_bytes: int = 32) -> str:
    # Gera e retorna uma chave simétrica aleatória em Base64
    key = os.urandom(size_bytes)
    return encode_b64(key)


def _aead_for(cipher: str, key: bytes):
    # Escolhe a cifra autenticada correta consoante a opção do utilizador
    if cipher in ("AES-128-GCM", "AES-192-GCM", "AES-256-GCM"):
        return AESGCM(key)
    if cipher == "ChaCha20-Poly1305":
        return ChaCha20Poly1305(key)
    raise ValueError(f"Cifra não suportada: {cipher}")


def encrypt_with_cipher(plaintext: bytes, key_b64: str, cipher: str) -> dict:
    # Cifragem autenticada com cifra escolhida pelo utilizador
    # Todas as cifras suportadas usam nonce de 96 bits
    key = decode_b64(key_b64)
    nonce = os.urandom(12)
    aead = _aead_for(cipher, key)
    ciphertext = aead.encrypt(nonce, plaintext, None)
    return {
        "nonce": encode_b64(nonce),
        "ciphertext": encode_b64(ciphertext)
    }


def decrypt_with_cipher(encrypted_data: dict, key_b64: str, cipher: str) -> bytes:
    # Decifra dados usando a cifra autenticada indicada
    key = decode_b64(key_b64)
    nonce = decode_b64(encrypted_data["nonce"])
    ciphertext = decode_b64(encrypted_data["ciphertext"])
    aead = _aead_for(cipher, key)
    return aead.decrypt(nonce, ciphertext, None)


def encrypt_with_aes_gcm(plaintext: bytes, key_b64: str) -> dict:
    # Função específica de cifragem AES-GCM 
    key = decode_b64(key_b64)
    nonce = os.urandom(12)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return {
        "nonce": encode_b64(nonce),
        "ciphertext": encode_b64(ciphertext)
    }


def decrypt_with_aes_gcm(encrypted_data: dict, key_b64: str) -> bytes:
    # Função específica de decifragem AES-GCM
    key = decode_b64(key_b64)
    nonce = decode_b64(encrypted_data["nonce"])
    ciphertext = decode_b64(encrypted_data["ciphertext"])

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def create_hmac_sha256(data: bytes, key_b64: str) -> str:
    # Cria um HMAC-SHA256 e retorna o valor em Base64
    key = decode_b64(key_b64)
    mac = hmac.new(key, data, hashlib.sha256).digest()
    return encode_b64(mac)


def verify_hmac_sha256(data: bytes, key_b64: str, mac_b64: str) -> bool:
    # Verifica um MAC comparando com o esperado
    expected_mac = create_hmac_sha256(data, key_b64)
    return hmac.compare_digest(expected_mac, mac_b64)

def generate_rsa_key_pair() -> tuple[bytes, bytes]:
    # Gera um par de chaves RSA e devolve PEMs codificados em bytes
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


def load_private_key(private_pem: bytes):
    # Converte PEM de chave privada em objeto de chave privada
    return serialization.load_pem_private_key(
        private_pem,
        password=None
    )


def load_public_key(public_pem: bytes):
    # Converte PEM de chave pública em objeto de chave pública
    return serialization.load_pem_public_key(public_pem)


def sign_data(data: bytes, private_pem: bytes) -> str:
    # Assina dados com chave privada usando PSS + SHA-256.
    private_key = load_private_key(private_pem)

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return encode_b64(signature)


def verify_signature(data: bytes, signature_b64: str, public_pem: bytes) -> bool:
    # Verifica a assinatura RSA, retorna False em caso de falha
    public_key = load_public_key(public_pem)
    signature = decode_b64(signature_b64)

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def encrypt_with_rsa_oaep(plaintext: bytes, public_pem: bytes) -> str:
    # Cifra plaintext com RSA-OAEP usando chave pública.
    public_key = load_public_key(public_pem)
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encode_b64(ciphertext)


def decrypt_with_rsa_oaep(ciphertext_b64: str, private_pem: bytes) -> bytes:
    # Decifra ciphertext RSA-OAEP usando chave privada.
    private_key = load_private_key(private_pem)
    ciphertext = decode_b64(ciphertext_b64)
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def derive_session_kek(seed_b64: str, counter: int) -> str:
    # Deriva a KEK da sessão usando o seed e o contador de login.
    # Cliente e servidor calculam a mesma KEK sem a enviar pela rede.
    seed = decode_b64(seed_b64)
    counter_bytes = counter.to_bytes(8, "big")
    mac = hmac.new(seed, counter_bytes, hashlib.sha256).digest()
    return encode_b64(mac)
