# install_ipfs.ps1 — simple helper to ensure IPFS is installed on Windows
# Usage: powershell -ExecutionPolicy Bypass -File .\scripts\install_ipfs.ps1
param()

function Has-Ipfs { return (Get-Command ipfs -ErrorAction SilentlyContinue) -ne  }

if (Has-Ipfs) {
  Write-Host "ipfs is already installed and on PATH." -ForegroundColor Green
  ipfs --version
  exit 0
}

Write-Host "ipfs not found. Follow these steps:" -ForegroundColor Yellow
Write-Host "1) Download Kubo (IPFS) for Windows (amd64) from: https://dist.ipfs.tech/#kubo" -ForegroundColor Yellow
Write-Host "2) Extract it (e.g., C:\ipfs) and add that folder to PATH." -ForegroundColor Yellow
Write-Host "3) Open a new terminal and run: ipfs init ; ipfs daemon" -ForegroundColor Yellow
