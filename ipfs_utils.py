import os
import requests

# Use HTTP base URL (set this in .env as IPFS_API=http://127.0.0.1:5001)
IPFS_API = os.getenv("IPFS_API", "http://127.0.0.1:5001")

def upload_to_ipfs(file_bytes: bytes) -> str:
    """Upload bytes to IPFS via HTTP API. Returns CID."""
    url = f"{IPFS_API}/api/v0/add"
    try:
        r = requests.post(url, files={"file": file_bytes})
        r.raise_for_status()
        return r.json()["Hash"]
    except Exception as e:
        raise RuntimeError(f"IPFS upload failed: {e}")

def download_from_ipfs(cid: str) -> bytes:
    """Download bytes from IPFS via HTTP API using /cat."""
    url = f"{IPFS_API}/api/v0/cat?arg={cid}"
    try:
        r = requests.post(url)
        r.raise_for_status()
        return r.content
    except Exception as e:
        raise RuntimeError(f"IPFS download failed: {e}")
