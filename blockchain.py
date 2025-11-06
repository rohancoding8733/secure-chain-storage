import json, os
from pathlib import Path
from hashlib import sha256

from dotenv import load_dotenv
from web3 import Web3
from eth_account import Account

load_dotenv()

GANACHE_URL     = os.getenv("GANACHE_URL", "http://127.0.0.1:7545")
PRIVATE_KEY     = os.getenv("PRIVATE_KEY")
ACCOUNT_ADDRESS = os.getenv("ACCOUNT_ADDRESS")

BASE       = Path(__file__).parent
BUILD_PATH = BASE / "build" / "FileRegistry.json"

with open(BUILD_PATH, "r", encoding="utf-8") as f:
    BUILD = json.load(f)

ABI              = BUILD["abi"]
CONTRACT_ADDRESS = BUILD["address"]

# --- Web3 setup ---
w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
assert w3.is_connected(), f"Cannot connect to {GANACHE_URL}"

acct = Account.from_key(PRIVATE_KEY)
assert acct.address.lower() == ACCOUNT_ADDRESS.lower(), "ACCOUNT_ADDRESS does not match PRIVATE_KEY"

contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)


# ------------------------ TX SENDER (robust) ------------------------ #
def _build_and_send(fn, tx_overrides=None):
    """
    Sign & send a state-changing contract function:
      - uses 'pending' nonce (avoids nonce races)
      - estimates gas and adds a safety multiplier
      - tries EIP-1559, falls back to legacy gas
      - retries up to 3 times on nonce/underpriced errors
    """
    txo = dict(tx_overrides or {})
    txo["from"]    = acct.address
    txo["chainId"] = w3.eth.chain_id

    # 1) Estimate gas (if revert, the estimate will raise a clearer error)
    try:
        gas_est = fn.estimate_gas({"from": acct.address})
    except Exception as e:
        # If Ganache hides revert reasons, give a hint:
        raise RuntimeError(
            f"Gas estimation failed (possible require()/revert). "
            f"Original: {e}"
        )
    # add safety margin
    txo["gas"] = int(gas_est * 2)

    def set_1559(t):
        t.pop("gasPrice", None)
        t["maxFeePerGas"]        = w3.to_wei(2, "gwei")
        t["maxPriorityFeePerGas"] = w3.to_wei(1, "gwei")

    def set_legacy(t):
        t.pop("maxFeePerGas", None); t.pop("maxPriorityFeePerGas", None)
        t["gasPrice"] = w3.to_wei(2, "gwei")

    last_err = None
    for _ in range(3):
        # fresh pending nonce each attempt
        txo["nonce"] = w3.eth.get_transaction_count(acct.address, "pending")

        # --- try EIP-1559 ---
        t = dict(txo)
        set_1559(t)
        signed = acct.sign_transaction(fn.build_transaction(t))
        try:
            tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
            return w3.eth.wait_for_transaction_receipt(tx_hash)
        except Exception as e:
            msg = str(e).lower()
            last_err = e

            # if fee type rejected or pricing issue → try legacy once
            if ("maxfeepergas" in msg) or ("eip-1559" in msg) or ("basefee" in msg) \
               or ("underpriced" in msg) or ("fee cap lower than block base fee" in msg):
                t = dict(txo)
                set_legacy(t)
                signed = acct.sign_transaction(fn.build_transaction(t))
                try:
                    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
                    return w3.eth.wait_for_transaction_receipt(tx_hash)
                except Exception as e2:
                    msg2 = str(e2).lower()
                    last_err = e2
                    # nonce race → retry loop with fresh pending nonce
                    if ("nonce" in msg2) or ("replacement transaction underpriced" in msg2):
                        continue
                    # otherwise bubble up
                    raise

            # nonce race with 1559 attempt → retry loop
            if ("nonce" in msg) or ("replacement transaction underpriced" in msg):
                continue

            # different error → bubble up
            raise

    # all attempts failed
    raise last_err


# ------------------------ Helpers you call from app.py ------------------------ #
def make_file_id(cid: str, filehash_hex: str) -> bytes:
    """Deterministic 32-byte id from CID + plaintext SHA-256 hex."""
    if filehash_hex.startswith("0x"):
        filehash_hex = filehash_hex[2:]
    return sha256((cid + filehash_hex).encode()).digest()


def add_file_record(file_id_bytes: bytes, filename: str, cid: str, filehash_hex: str):
    """
    Matches Solidity: addFile(bytes32, string, string, bytes32)
    NOTE: calling this twice with the same file_id will revert (Already exists).
    """
    fh_hex = filehash_hex[2:] if filehash_hex.startswith("0x") else filehash_hex
    fh = bytes.fromhex(fh_hex)
    if len(fh) != 32:
        raise ValueError("filehash_hex must be 32 bytes (64 hex chars).")

    fn = contract.functions.addFile(file_id_bytes, filename, cid, fh)
    return _build_and_send(fn)


def get_file_meta(file_id_bytes: bytes):
    """
    Returns dict: owner, filename, cid, fileHashHex (0x...)
    Call the view from the owner address so access check passes.
    """
    result = contract.functions.getFile(file_id_bytes).call({"from": acct.address})
    owner, filename, cid, filehash = result
    return {
        "owner": owner,
        "filename": filename,
        "cid": cid,
        "fileHashHex": "0x" + filehash.hex(),
    }


def grant_access(file_id_bytes: bytes, user_addr: str):
    fn = contract.functions.grantAccess(file_id_bytes, Web3.to_checksum_address(user_addr))
    return _build_and_send(fn)


def revoke_access(file_id_bytes: bytes, user_addr: str):
    fn = contract.functions.revokeAccess(file_id_bytes, Web3.to_checksum_address(user_addr))
    return _build_and_send(fn)
