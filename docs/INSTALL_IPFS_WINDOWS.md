# Install IPFS (Kubo) on Windows

1. Download **Kubo (IPFS)** for Windows (amd64) from the official site:  
   https://dist.ipfs.tech/#kubo

2. Extract to C:\ipfs (for example) and add that folder to **PATH**.

3. First-time setup:
   `powershell
   ipfs init
   ipfs daemon
Verify API is up at http://127.0.0.1:5001.
powershell -ExecutionPolicy Bypass -File .\scripts\install_ipfs.ps1
