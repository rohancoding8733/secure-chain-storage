# app.py — Modern UI with ttkbootstrap (thread-safe prompts)
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog  # use simpledialog for all prompts

from dotenv import load_dotenv
from ttkbootstrap import Window, Style
from ttkbootstrap.constants import *

# project imports
from crypto_utils import encrypt_file, decrypt_to_bytes, sha256_hex
from ipfs_utils import upload_to_ipfs, download_from_ipfs
from blockchain import make_file_id, add_file_record, get_file_meta

load_dotenv()

APP_TITLE = "Secure Chain Storage — AES + IPFS + Ethereum"


class App(Window):
    def __init__(self):
        super().__init__(themename="darkly")  # try: "cosmo", "solar", "superhero", "flatly"
        self.title(APP_TITLE)
        self.geometry("860x580")
        self.minsize(820, 540)

        # State
        self._busy = False
        self.current_cid = None
        self.current_file_id = None
        self.current_sha = None

        self._build_ui()

    # ---------- UI ----------
    def _build_ui(self):
        # Header
        header = tk.Frame(self)
        header.pack(fill="x", padx=12, pady=(12, 6))

        title = tk.Label(
            header,
            text="Secure Chain Storage",
            font=("Segoe UI", 18, "bold"),
            anchor="w",
        )
        title.pack(side="left")

        # Theme switcher
        theme_btn = tk.Menubutton(header, text="Theme", relief="raised")
        menu = tk.Menu(theme_btn, tearoff=0)
        theme_btn["menu"] = menu
        for th in ("darkly", "superhero", "cyborg", "solar", "cosmo", "flatly", "litera", "pulse"):
            menu.add_command(label=th, command=lambda t=th: self._switch_theme(t))
        theme_btn.pack(side="right", padx=6)

        # Action bar
        bar = tk.Frame(self)
        bar.pack(fill="x", padx=12, pady=(0, 8))

        # Buttons call orchestration methods that gather input on main thread,
        # then spawn a worker thread for heavy work.
        self.btn_upload = tk.Button(
            bar, text="Upload File", command=self.upload_flow,
            padx=10, pady=6, bg="#0d6efd", fg="white", relief="raised"
        )
        self.btn_download = tk.Button(
            bar, text="Download + Decrypt", command=self.download_flow,
            padx=10, pady=6, bg="#198754", fg="white", relief="raised"
        )
        self.btn_verify = tk.Button(
            bar, text="Verify by File ID", command=self.verify_flow,
            padx=10, pady=6, bg="#0dcaf0", fg="black", relief="raised"
        )
        self.btn_upload.pack(side="left", padx=4)
        self.btn_download.pack(side="left", padx=4)
        self.btn_verify.pack(side="left", padx=4)

        # Copy shortcuts for last results
        self.btn_copy_cid = tk.Button(bar, text="Copy CID",
                                      command=lambda: self._copy_clip(self.current_cid), state="disabled")
        self.btn_copy_fid = tk.Button(bar, text="Copy File ID",
                                      command=lambda: self._copy_clip(self.current_file_id), state="disabled")
        self.btn_copy_sha = tk.Button(bar, text="Copy SHA-256",
                                      command=lambda: self._copy_clip(self.current_sha), state="disabled")
        self.btn_copy_cid.pack(side="right", padx=4)
        self.btn_copy_fid.pack(side="right", padx=4)
        self.btn_copy_sha.pack(side="right", padx=4)

        # Separator
        sep = tk.Frame(self, height=1, bg="#2b2f32")
        sep.pack(fill="x", padx=12, pady=6)

        # Log area
        self.log = tk.Text(self, height=18, wrap="word", relief="flat", bd=0)
        self.log.configure(bg="#1e2124", fg="#e6e6e6", insertbackground="#e6e6e6")
        self.log.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        # Progress + status bar
        bottom = tk.Frame(self)
        bottom.pack(fill="x", padx=12, pady=(0, 10))

        import ttkbootstrap as tb
        self.progress = tb.Progressbar(bottom, mode="indeterminate", bootstyle=INFO)
        self.progress.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self.status = tk.Label(bottom, text="Ready.", anchor="e")
        self.status.pack(side="right")

    def _switch_theme(self, name: str):
        Style(theme=name)
        self.update_idletasks()

    # ---------- helpers ----------
    def _set_busy(self, busy: bool):
        self._busy = busy
        state = "disabled" if busy else "normal"
        for b in (self.btn_upload, self.btn_download, self.btn_verify):
            b.configure(state=state)
        if busy:
            self.progress.start(10)
            self._status("Working...")
        else:
            self.progress.stop()
            self._status("Ready.")

    def _status(self, s: str):
        self.status.config(text=s)
        self.status.update_idletasks()

    def _log(self, s: str):
        self.log.insert("end", s + "\n")
        self.log.see("end")
        self.log.update_idletasks()

    def _copy_clip(self, text):
        if not text:
            messagebox.showwarning("Nothing to copy", "No value is available yet.")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self._status("Copied to clipboard")

    # ---------- flows (thread-safe) ----------
    def upload_flow(self):
        """Gather inputs on main thread, then run worker in background."""
        path = filedialog.askopenfilename(title="Select file to encrypt & upload")
        if not path:
            return
        filename = os.path.basename(path)
        pw = simpledialog.askstring("Password for encryption", "Password:", show="*")
        if not pw:
            messagebox.showwarning("Cancelled", "Password required.")
            return

        def worker():
            try:
                self._set_busy(True)
                # 1) Encrypt
                self._log(f"[1/4] Encrypting {filename} with AES-256-GCM...")
                enc_bytes, sha_hex = encrypt_file(path, pw)
                self.current_sha = sha_hex
                self._log(f"    SHA-256 (plaintext) = {sha_hex}")

                # 2) Upload to IPFS
                self._log("[2/4] Uploading encrypted bytes to IPFS...")
                cid = upload_to_ipfs(enc_bytes)
                self.current_cid = cid
                self._log(f"    IPFS CID = {cid}")

                # 3) Compute fileId
                self._log("[3/4] Computing fileId (sha256(cid + sha256))...")
                file_id = make_file_id(cid, sha_hex)
                self.current_file_id = "0x" + file_id.hex()

                # 4) Write on-chain
                self._log("[4/4] Writing metadata to blockchain...")
                receipt = add_file_record(file_id, filename, cid, sha_hex)
                blk = receipt.get("blockNumber", "?")
                self._log(f"    Tx mined in block {blk} ✔")

                # Enable quick-copy buttons
                self.btn_copy_cid.configure(state="normal")
                self.btn_copy_fid.configure(state="normal")
                self.btn_copy_sha.configure(state="normal")

                self._log(
                    "\n✅ Upload complete!\n"
                    f"File ID (hex): {self.current_file_id}\n"
                    f"CID:          {cid}\n"
                    f"SHA-256:      {sha_hex}\n"
                    "Keep the password safe — it is required to decrypt.\n"
                )
            except Exception as e:
                messagebox.showerror("Error", str(e))
                self._log(f"Error: {e}")
            finally:
                self._set_busy(False)

        threading.Thread(target=worker, daemon=True).start()

    def download_flow(self):
        """Gather fileId & password on main thread, then run worker."""
        file_id_hex = simpledialog.askstring("Download + Decrypt", "Paste the fileId (0x... or hex):")
        if not file_id_hex:
            return
        fid = file_id_hex.lower().strip()
        if fid.startswith("0x"):
            fid = fid[2:]
        try:
            file_id = bytes.fromhex(fid)
        except ValueError:
            messagebox.showerror("Error", "Invalid hex for fileId")
            return

        pw = simpledialog.askstring("Password to decrypt", "Password:", show="*")
        if not pw:
            messagebox.showwarning("Cancelled", "Password required.")
            return

        def worker():
            try:
                self._set_busy(True)
                # Read metadata
                self._log("Querying blockchain for metadata ...")
                meta = get_file_meta(file_id)
                if isinstance(meta, dict):
                    owner, filename, cid, sha_on_chain = (
                        meta["owner"],
                        meta["filename"],
                        meta["cid"],
                        meta["fileHashHex"].removeprefix("0x"),
                    )
                else:
                    owner, filename, cid, filehash_bytes = meta
                    sha_on_chain = filehash_bytes.hex()

                self._log(f"  Owner: {owner}\n  Filename: {filename}\n  CID: {cid}\n  SHA-256: {sha_on_chain}")

                # IPFS
                self._log("Fetching encrypted bytes from IPFS...")
                enc_bytes = download_from_ipfs(cid)

                # Decrypt
                self._log("Decrypting ...")
                plaintext = decrypt_to_bytes(enc_bytes, pw)

                # Integrity
                sha_now = sha256_hex(plaintext)
                ok = (sha_now.lower() == sha_on_chain.lower())
                self._log(f"Integrity check: computed SHA-256 = {sha_now} -> {'OK' if ok else 'MISMATCH'}")

                # Save
                out = filedialog.asksaveasfilename(
                    title="Save decrypted file as", initialfile=filename or "decrypted_output.bin"
                )
                if not out:
                    self._log("Save cancelled.")
                    return
                with open(out, "wb") as f:
                    f.write(plaintext)
                self._log(f"Saved decrypted file to: {out}")
                if not ok:
                    messagebox.showwarning(
                        "Integrity mismatch",
                        "Decrypted file saved, but hash did not match on-chain record.",
                    )
            except Exception as e:
                messagebox.showerror("Error", str(e))
                self._log(f"Error: {e}")
            finally:
                self._set_busy(False)

        threading.Thread(target=worker, daemon=True).start()

    def verify_flow(self):
        """Gather fileId on main thread, then run worker to query metadata."""
        file_id_hex = simpledialog.askstring("Verify by File ID", "Paste the fileId (0x... or hex):")
        if not file_id_hex:
            return
        fid = file_id_hex.strip()
        if fid.lower().startswith("0x"):
            fid = fid[2:]
        try:
            file_id = bytes.fromhex(fid)
        except ValueError:
            messagebox.showerror("Error", "Invalid hex for fileId")
            return

        def worker():
            try:
                self._set_busy(True)
                meta = get_file_meta(file_id)
                if isinstance(meta, dict):
                    owner, filename, cid, sha_hex = meta["owner"], meta["filename"], meta["cid"], meta["fileHashHex"]
                else:
                    owner, filename, cid, filehash_bytes = meta
                    sha_hex = "0x" + filehash_bytes.hex()

                self._log(
                    "Metadata on-chain:\n"
                    f"Owner:   {owner}\n"
                    f"Filename:{filename}\n"
                    f"CID:     {cid}\n"
                    f"SHA-256: {sha_hex}\n"
                    "(Downloading requires access and password.)\n"
                )
            except Exception as e:
                messagebox.showerror("Error", f"Verify failed: {e}")
                self._log(f"Error: {e}")
            finally:
                self._set_busy(False)

        threading.Thread(target=worker, daemon=True).start()


if __name__ == "__main__":
    App().mainloop()
