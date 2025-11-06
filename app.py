import os, tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from dotenv import load_dotenv

from crypto_utils import encrypt_file, decrypt_to_bytes, sha256_hex
from ipfs_utils import upload_to_ipfs, download_from_ipfs
from blockchain import make_file_id, add_file_record, get_file_meta

load_dotenv()

APP_TITLE = "Secure Chain Storage (AES + IPFS + Ethereum)"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("720x520")
        self.minsize(720, 520)
        self._ui()

    def _ui(self):
        pad = {"padx": 10, "pady": 10}

        ttk.Label(self, text="Secure File Storage (Local Demo)", font=("Segoe UI", 16, "bold")).pack(**pad)
        ttk.Label(self, text="Encrypt with AES-256, store on IPFS, register on local Ethereum (Ganache).").pack(**pad)

        bar = ttk.Frame(self); bar.pack(fill="x", **pad)
        ttk.Button(bar, text="Upload File",        command=self.upload_flow).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Button(bar, text="Download + Decrypt", command=self.download_flow).grid(row=0, column=1, padx=5, pady=5, sticky="w")
        ttk.Button(bar, text="Verify by File ID",  command=self.verify_flow).grid(row=0, column=2, padx=5, pady=5, sticky="w")
        ttk.Button(bar, text="Grant Access",       command=self._not_implemented).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        ttk.Button(bar, text="Revoke Access",      command=self._not_implemented).grid(row=1, column=1, padx=5, pady=5, sticky="w")

        ttk.Separator(self, orient="horizontal").pack(fill="x", pady=8)
        self.out = tk.Text(self, height=18, wrap="word"); self.out.pack(fill="both", expand=True, padx=10, pady=10)
        self.status = ttk.Label(self, text="Ready.", anchor="w"); self.status.pack(fill="x")

    # --- helpers ---
    def log(self, s: str):
        self.out.insert("end", s + "\n"); self.out.see("end"); self.status.config(text=s); self.update_idletasks()

    def ask_password(self, prompt="Enter a password (keep it safe!)"):
        pw = simpledialog.askstring("Password", prompt, show="*")
        if not pw: messagebox.showwarning("Cancelled", "Password required.")
        return pw

    def prompt(self, title):
        win = tk.Toplevel(self); win.title(title); win.grab_set()
        v = tk.StringVar(); e = tk.Entry(win, textvariable=v, width=64); e.pack(padx=10, pady=10); e.focus_set()
        out = {"val": None}
        ttk.Button(win, text="OK", command=lambda: (out.update(val=v.get().strip()), win.destroy())).pack(pady=8)
        self.wait_window(win); return out["val"]

    # --- flows ---
    def upload_flow(self):
        path = filedialog.askopenfilename(title="Select file to encrypt & upload")
        if not path: return
        filename = os.path.basename(path)
        pw = self.ask_password()
        if not pw: return

        try:
            self.log(f"[1/4] Encrypting {filename} with AES-256-GCM...")
            enc_bytes, sha_hex = encrypt_file(path, pw)     # your crypto_utils returns (encrypted, sha_hex)
            self.log(f"    SHA-256 (plaintext) = {sha_hex}")

            self.log("[2/4] Uploading encrypted bytes to IPFS...")
            cid = upload_to_ipfs(enc_bytes)                  # <-- no get_client, direct REST call
            self.log(f"    IPFS CID = {cid}")

            self.log("[3/4] Computing fileId (keccak of cid+sha256)...")
            file_id = make_file_id(cid, sha_hex)

            self.log("[4/4] Writing metadata to blockchain...")
            receipt = add_file_record(file_id, filename, cid, sha_hex)
            self.log(f"    Tx mined in block {receipt['blockNumber']}.")

            self.log(
                "✔ Done!\n"
                f"File ID (hex): {file_id.hex()}\n"
                f"Filename: {filename}\n"
                f"CID: {cid}\n"
                f"SHA-256: {sha_hex}\n"
                "Keep the password safe — it's required to decrypt.\n"
            )
        except Exception as e:
            messagebox.showerror("Error", str(e)); self.log(f"Error: {e}")

    def download_flow(self):
        file_id_hex = self.prompt("Paste the fileId (0x... or hex)")
        if not file_id_hex: return
        fid = file_id_hex[2:] if file_id_hex.lower().startswith("0x") else file_id_hex
        try:
            file_id = bytes.fromhex(fid)
        except ValueError:
            messagebox.showerror("Error", "Invalid hex for fileId"); return

        try:
            self.log("Querying blockchain for metadata ...")
            meta = get_file_meta(file_id)

            # Support both dict (new) and tuple (old)
            if isinstance(meta, dict):
                owner, filename, cid, sha_on_chain = meta["owner"], meta["filename"], meta["cid"], meta["fileHashHex"].removeprefix("0x")
            else:
                owner, filename, cid, filehash_bytes = meta
                sha_on_chain = filehash_bytes.hex()

            self.log(f"  Owner: {owner}\n  Filename: {filename}\n  CID: {cid}\n  SHA-256: {sha_on_chain}")

            self.log("Fetching encrypted bytes from IPFS...")
            enc_bytes = download_from_ipfs(cid)              # <-- direct REST call

            pw = self.ask_password("Enter password to decrypt:")
            if not pw: return
            self.log("Decrypting...")
            plaintext = decrypt_to_bytes(enc_bytes, pw)

            sha_now = sha256_hex(plaintext)
            ok = (sha_now.lower() == sha_on_chain.lower())
            self.log(f"Integrity check: computed SHA-256 = {sha_now} -> {'OK' if ok else 'MISMATCH'}")

            save_to = filedialog.asksaveasfilename(defaultextension="", initialfile=filename, title="Save decrypted file as...")
            if save_to:
                with open(save_to, "wb") as f: f.write(plaintext)
                self.log(f"Saved decrypted file to {save_to}")
                if not ok:
                    messagebox.showwarning("Integrity mismatch", "Decrypted file saved, but hash did not match on-chain record.")
        except Exception as e:
            messagebox.showerror("Error", str(e)); self.log(f"Error: {e}")

    def verify_flow(self):
        file_id_hex = self.prompt("Paste the fileId (0x... or hex) to view metadata.")
        if not file_id_hex: return
        fid = file_id_hex[2:] if file_id_hex.lower().startswith("0x") else file_id_hex
        try:
            file_id = bytes.fromhex(fid)
        except ValueError:
            messagebox.showerror("Error", "Invalid hex for fileId"); return

        try:
            meta = get_file_meta(file_id)
            if isinstance(meta, dict):
                owner, filename, cid, sha_hex = meta["owner"], meta["filename"], meta["cid"], meta["fileHashHex"]
            else:
                owner, filename, cid, filehash_bytes = meta
                sha_hex = "0x" + filehash_bytes.hex()

            self.log(
                "Metadata on-chain:\n"
                f"Owner:   {owner}\n"
                f"Filename:{filename}\n"
                f"CID:     {cid}\n"
                f"SHA-256: {sha_hex}\n"
                "(Downloading requires access and password.)\n"
            )
        except Exception as e:
            messagebox.showerror("Error", str(e)); self.log(f"Error: {e}")

    def _not_implemented(self):
        messagebox.showinfo("Note", "Use command-line helpers in blockchain.py to grant/revoke for now.")

if __name__ == "__main__":
    App().mainloop()
