# Secure File Storage with AES-256 + IPFS + Local Ethereum (Ganache) — Tkinter GUI

This project is a **local demo** that encrypts files with AES-256-GCM, uploads the encrypted bytes to **IPFS**, and stores file metadata + access control on a local **Ethereum** blockchain (Ganache). A simple **Tkinter** desktop app lets you upload, verify, and download+decrypt files.

> **What the chain stores:** filename, owner address, IPFS CID for the encrypted file, and the SHA-256 hash of the **plaintext**.  
> **Access control:** Only the owner (uploader) or addresses granted by owner can read metadata (get CID) and thus download via the app.  
> **Integrity:** On download, the app recomputes SHA-256 of the decrypted bytes and compares with the on-chain hash.

---

## 0) Prerequisites (all free)

- **Python 3.10+** (preferably 3.11)
- **Node.js** (only if you choose to install the Ganache Desktop via Node; GUI installer also available)
- **Ganache** (Desktop app recommended) — Local Ethereum test network  
  Download: https://archive.trufflesuite.com/ganache/ (or search “Ganache download”)
- **Go-IPFS** (IPFS node) — Install & run a local IPFS daemon  
  Download: https://docs.ipfs.tech/install/ (choose your OS)

> On Windows, allow both tools through your firewall on first run.

---

## 1) Start your local services

### 1.1 Start Ganache
- Launch **Ganache** (GUI).
- Create a **New Workspace**; set the RPC server to `http://127.0.0.1:7545` (default).
- Copy **one account's Private Key** and **Address** — you'll put these in `.env`.

> Chain ID is usually `1337` or `5777` depending on Ganache version — the code reads it dynamically.

### 1.2 Start IPFS
Open a terminal and run:
```bash
ipfs init   # only once
ipfs daemon
```
The HTTP API will listen on `/ip4/127.0.0.1/tcp/5001` by default.

---

## 2) Set up the project

```bash
# 2.1 — create a virtualenv (recommended)
python -m venv .venv
# Windows:
.\.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# 2.2 — install dependencies
pip install -r requirements.txt
```

Create `.env` from example and fill it:
```bash
copy .env.example .env       # Windows
# or
cp .env.example .env         # macOS/Linux
```

Edit `.env` and set:
```
GANACHE_URL=http://127.0.0.1:7545
PRIVATE_KEY=0x...from Ganache...
ACCOUNT_ADDRESS=0x...matching the key...
IPFS_API=/ip4/127.0.0.1/tcp/5001
```

---

## 3) Deploy the smart contract (Python-only)

We compile Solidity with **py-solc-x** and deploy with **web3.py**.

```bash
python deploy_contract.py
```
You should see:
```
Deployed FileRegistry at: 0xABCDEF...
```
This address is saved to `build/FileRegistry.json` so the app can use it.

> If you change the contract, re-run the deploy script.

---

## 4) Run the desktop app

```bash
python app.py
```

### Upload flow
1. Pick a file.
2. Enter a password (used to derive a 256-bit AES key via PBKDF2-HMAC-SHA256).
3. App encrypts the file (AES-256-GCM), computes **SHA-256 of the plaintext**, uploads encrypted bytes to IPFS, then writes metadata to the chain.
4. The app prints your **fileId** (keccak(cid + sha256)), the **CID**, and the hash.

> **Keep the password safe.** Without it, the downloaded data is useless.

### Download flow
1. Paste `fileId` in hex (with or without `0x`).
2. The contract checks your access. If allowed, the app fetches the CID + hash, downloads encrypted bytes from IPFS, asks for your password, decrypts, verifies integrity, and saves the file.

---

## 5) Granting / revoking access

The UI keeps the demo minimal. Use these helper functions programmatically:

```python
from blockchain import grant_access, revoke_access, make_file_id

file_id = make_file_id("<CID>", "<SHA256_HEX>")
grant_access(file_id, "0xFriendAddress")
revoke_access(file_id, "0xFriendAddress")
```

> Only the **owner** (uploader account) can call these.

---

## 6) How IDs & integrity work

- `fileId = keccak256(str(cid) + str(sha256_plaintext_hex))` — deterministic identifier.
- On-chain we store: `owner`, `filename`, `cid`, `fileHash` (bytes32).
- On download, we compute SHA-256 of the **decrypted** bytes and compare with on-chain `fileHash` to detect corruption/tampering.

---

## 7) Troubleshooting

- **Cannot connect to Ethereum**: ensure Ganache is running on `127.0.0.1:7545`. Check `.env`.
- **ACCOUNT_ADDRESS mismatch**: the deploy & tx signing uses `PRIVATE_KEY`; ensure `ACCOUNT_ADDRESS` is that key’s address.
- **IPFS errors**: run `ipfs daemon`. If your API listens elsewhere, update `IPFS_API` in `.env`.
- **Contract not deployed**: run `python deploy_contract.py` before `app.py`.
- **Solidity not found**: the deploy script installs `solc 0.8.20` for you. If corporate proxies block it, install manually.

---

## 8) Security notes (for a real product)
- Store only **encrypted** data off-chain. Never store plaintext or passwords.
- Use a stronger KDF (Argon2id) and increase iterations depending on UX.
- Consider **hardware wallets** for keys, and use proper **access logs**.
- Move from local IPFS to a pinned/IPFS cluster, and from Ganache to testnets/mainnet with audited contracts.
- Add **rate limits**, **password strength checks**, and **secure secret storage**.

---

## 9) Project layout

```
secure-chain-storage/
├── app.py
├── blockchain.py
├── crypto_utils.py
├── deploy_contract.py
├── ipfs_utils.py
├── requirements.txt
├── .env.example
├── build/
│   └── FileRegistry.json  # created after deploy
└── contracts/
    └── FileRegistry.sol
```

---

## 10) Quick demo script (optional)

```python
# demo.py — Upload then download immediately (headless)
from dotenv import load_dotenv
from ipfs_utils import get_client, add_bytes, get_bytes
from crypto_utils import encrypt_file, decrypt_to_bytes, sha256_hex
from blockchain import make_file_id, add_file_record, get_file_meta

load_dotenv()
password = "testpass123"

enc, digest = encrypt_file("sample.pdf", password)
client = get_client()
cid = add_bytes(client, enc, filename="sample.pdf.enc")
fid = make_file_id(cid, digest)
add_file_record(fid, "sample.pdf", cid, digest)

owner, fname, cid2, h = get_file_meta(fid)
enc2 = get_bytes(client, cid2)
pt = decrypt_to_bytes(enc2, password)
print("Integrity:", sha256_hex(pt) == h.hex())
```
