# MR.SMITH

Plataforma para cifrar, autenticar e assinar ficheiros entre utilizadores usando um agente de confiança (TTP).

Trabalho da unidade curricular **Segurança Informática / Cibersegurança** (UBI, 2025/26).

---

## O que faz

- **Registo** e **autenticação** de utilizadores junto do agente de confiança
- **3 modos de envio** de ficheiros entre utilizadores online:
  - **HMAC** — em claro, com código de autenticação (integridade)
  - **Cifrado** — AES-128/192/256-GCM ou ChaCha20-Poly1305 à escolha (confidencialidade + integridade)
  - **Assinado** — assinatura RSA-PSS do agente (autenticidade)

---

## Pré-requisitos

- **Python 3.10 ou superior**
- Bibliotecas:
  ```bash
  pip3 install cryptography textual --break-system-packages
  ```
  (a flag `--break-system-packages` só é necessária em Debian/Ubuntu/WSL recentes)

---

## Como correr (1 máquina, demo local)

Abre 3 terminais na pasta do projeto:

**Terminal 1 — Servidor:**
```bash
python3 server.py
```

**Terminal 2 — Cliente Alice (TUI):**
```bash
python3 client_tui.py
```

**Terminal 3 — Cliente Bob (TUI):**
```bash
python3 client_tui.py
```

Em cada cliente: **Registar** → introduzir username/password → **Entrar**.

Depois: escrever destinatário + caminho do ficheiro (ex.: `sent/segredo.txt`), escolher o modo, e **Enviar**.

O destinatário abre a **Caixa de entrada** (`Ctrl+I`) e seleciona o ficheiro para o receber.

---

## Como correr em rede (máquinas diferentes)

**Máquina A — Servidor:**
```bash
python3 server.py
```

Ao arrancar, o servidor mostra o seu IP. Exemplo:
```
[MR.SMITH] IP desta máquina na rede: 192.168.1.50
```

**Máquinas B, C, ... — Clientes:**
```bash
python3 client_tui.py 192.168.1.50
```
(substituir pelo IP que o servidor anunciou)

Pré-requisitos de rede:
- Todas as máquinas na mesma rede local
- Porta 5000 aberta no servidor (firewall)

---

## Alternativa CLI (sem interface gráfica)

Se preferires linha de comandos:
```bash
python3 client.py            # local
python3 client.py 192.168.1.50  # em rede
```

---

## Estrutura do projeto

```
MrSmith/
├── server.py            Agente de confiança (TTP)
├── client.py            Cliente em linha de comandos
├── client_tui.py        Cliente com interface gráfica (Textual)
├── crypto_utils.py      Primitivas criptográficas
├── sent/                Ficheiros prontos para enviar
└── README.md
```

Pastas criadas automaticamente em runtime:
- `users.json` — base de dados de utilizadores (servidor)
- `keys/` — par RSA do agente para assinaturas (servidor)
- `client_keys/<user>.seed` — seed local cifrado com a password (cliente)
- `inbox/` — ficheiros recebidos (cliente)

---

## Modelo de segurança (resumo)

- Passwords nunca viajam pela rede (challenge-response com HMAC)
- Passwords nunca são guardadas em claro (PBKDF2-HMAC-SHA256, 200 000 iterações)
- Seed de longa duração trocado via RSA-OAEP no registo
- KEK de sessão derivada de HMAC(seed, login_counter) — muda a cada login
- AES-GCM e ChaCha20-Poly1305 são cifras autenticadas (confidencialidade + integridade)
- Assinaturas RSA-2048 com padding PSS + SHA-256

Para mais detalhes, abrir o cliente e consultar a **Ajuda** integrada (`Ctrl+H` no TUI).

---

## Atalhos do TUI

| Ecrã | Atalho | Ação |
|---|---|---|
| Login | `Esc` | Sair |
| Dashboard | `Ctrl+I` | Caixa de entrada |
| Dashboard | `Ctrl+H` | Ajuda |
| Dashboard | `Ctrl+L` | Logout |
| Inbox | `Enter` | Receber ficheiro selecionado |
| Inbox | `R` | Atualizar |
| Inbox / Help | `Esc` | Voltar ao dashboard |
