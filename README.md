<div align="center">

# ⚡ Secure Chain Storage

**🔐 AES-256 + ☁️ IPFS + ⛓️ Ethereum (Ganache)**  
*Encrypt locally. Store globally. Verify immutably.*

---

<p>
  <a href="https://www.python.org/">
    <img alt="Python" src="https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white" />
  </a>
  <a href="https://ipfs.tech/">
    <img alt="IPFS" src="https://img.shields.io/badge/Storage-IPFS-65C2CB?logo=ipfs&logoColor=white" />
  </a>
  <a href="https://trufflesuite.com/ganache/">
    <img alt="Ganache" src="https://img.shields.io/badge/Blockchain-Ganache%20(Local)-F6C343?logo=ethereum&logoColor=white" />
  </a>
  <a href="https://soliditylang.org/">
    <img alt="Solidity" src="https://img.shields.io/badge/Solidity-0.8.x-363636?logo=solidity&logoColor=white" />
  </a>
  <a href="LICENSE">
    <img alt="License" src="https://img.shields.io/badge/License-MIT-2ea44f" />
  </a>
</p>

</div>

---

## 🌍 Overview

**Secure Chain Storage** is a decentralized file storage app that merges **cryptography**, **blockchain**, and **distributed storage** into one seamless experience.  

💡 It ensures your files are **encrypted locally**, **stored securely on IPFS**, and **verified transparently on Ethereum**.

No central servers. No data leaks.  
Just you, your files, and pure security.

---

## 🧩 How It Works

```text
📁 File → 🔒 AES-256 Encryption (local) → 🧱 Encrypted Bytes
                        │
                        ├── ☁️ Upload to IPFS → 🔗 CID (Unique Hash)
                        │
                        └── ⛓️ Record on Ethereum (Owner, CID, SHA-256, Filename)

fileId = SHA256(CID + plaintext_hash)
```

🧠 This combination ensures:
- Your file content is unreadable without the password.
- Its existence and ownership are verifiable on blockchain.
- The hash guarantees **integrity** — no tampering possible.

---

## ✨ Key Features

| 🚀 Feature | 💡 Description |
|-------------|----------------|
| 🔐 **AES-256 Encryption** | Industry-standard encryption using password-derived keys (PBKDF2 + AES-GCM). |
| ☁️ **Decentralized Storage (IPFS)** | Files stored across nodes instead of a single server. Fast, fault-tolerant, censorship-resistant. |
| ⛓️ **Blockchain Metadata** | Ethereum smart contract records file identity, owner, and checksum — immutable and auditable. |
| 🧾 **Integrity Verification** | SHA-256 ensures your downloaded file matches the original. |
| 🧩 **Access Control** | Owners can grant or revoke permissions for file metadata visibility. |
| 🖥️ **Modern GUI** | Built in Tkinter with a clean interface for uploads, downloads, and verification. |

---

## 🧱 Tech Stack

| Layer | Technology |
|--------|-------------|
| Frontend | Tkinter (Python GUI) |
| Encryption | AES-256-GCM, PBKDF2 (from `cryptography` library) |
| Storage | IPFS Kubo (local daemon) |
| Blockchain | Ethereum test network (Ganache + Solidity 0.8.x) |
| Integration | `web3.py`, `requests`, `dotenv` |

---

## ⚙️ Installation (Windows)

```powershell
# Clone repository
 git clone https://github.com/<your-username>/secure-chain-storage.git
 cd secure-chain-storage

# Create a virtual environment
 python -m venv .venv
 .\.venv\Scripts\Activate

# Install dependencies
 pip install -r requirements.txt
 pip install requests cryptography

# Copy the example environment file
 copy .env.example .env
 # Fill your Ganache account PRIVATE_KEY and ACCOUNT_ADDRESS

# Start local services
 ipfs init
 ipfs daemon
# Open Ganache GUI at http://127.0.0.1:7545
```

---

## ▶️ Running the Application

```powershell
# Deploy the smart contract (only needed after Ganache reset)
 python deploy_contract.py

# Launch the app GUI
 python app.py
```

Once opened, the GUI allows file upload, encryption, and verification operations.

---

## 🧠 Workflow Explained

1. **Upload File**  
   - Select any file. The app encrypts it locally using AES-256-GCM.  
   - The encrypted data is uploaded to IPFS.  
   - A unique CID and SHA-256 hash are generated.  
   - Metadata (CID, hash, owner) is recorded on the blockchain.

2. **Download + Decrypt File**  
   - Enter fileId (auto-generated) and your password.  
   - The app retrieves the encrypted data from IPFS and decrypts it locally.  
   - The integrity check verifies it matches the on-chain hash.

3. **Verify File Integrity**  
   - Check whether a file’s hash matches the blockchain record.

4. **Access Control (CLI)**  
   - Grant or revoke access to other Ethereum addresses.

---

## 🧰 Access Control Example

```python
from dotenv import load_dotenv; load_dotenv()
from blockchain import grant_access, revoke_access, make_file_id
from web3 import Web3

cid     = "QmExampleCID123"  # from IPFS upload log
sha_hex = "abcdef123456..."  # plaintext SHA-256 hash
fid     = make_file_id(cid, sha_hex)
user    = Web3.to_checksum_address("0xRecipientAddress")

grant_access(fid, user)   # grant read access
# revoke_access(fid, user)  # revoke access
```

---

## 🧭 Troubleshooting

| Problem | Possible Solution |
|----------|------------------|
| ❌ *Access Denied* | Only the owner or authorized addresses can read metadata. Use grant_access. |
| ⚠️ *Nonce Error* | Restart Ganache, redeploy contract (`python deploy_contract.py`). |
| ⛔ *Invalid Opcode / Out of Gas* | Contract rejects duplicate fileIds. Upload unique files. |
| 📡 *IPFS Not Found* | Ensure IPFS daemon is running and API is reachable at `127.0.0.1:5001`. |
| 🧩 *Missing Module* | Run `pip install cryptography web3 requests`. |

---

## 🔐 Security & Best Practices

- 🧱 Private keys are stored **only** in your local `.env` (never commit them).
- 🔒 Files are encrypted **before** leaving your device.
- 🧾 Smart contracts are immutable — once uploaded, records cannot be faked.
- 🌐 IPFS ensures distributed storage; no single point of failure.
- ⚡ Always back up your `.env` and encryption password securely.

---

## 🧾 License

This project is distributed under the **MIT License** — open for learning, modification, and contribution.

<div align="center">

💙 Built for developers who value **privacy, transparency, and decentralization.**  
_“Own your data, control your security.”_

</div>

