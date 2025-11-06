import json, os, sys
from pathlib import Path
from dotenv import load_dotenv
from web3 import Web3
from solcx import compile_standard, install_solc

load_dotenv()

GANACHE_URL = os.getenv("GANACHE_URL", "http://127.0.0.1:7545")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
ACCOUNT_ADDRESS = os.getenv("ACCOUNT_ADDRESS")

BASE = Path(__file__).parent
CONTRACT_PATH = BASE / "contracts" / "FileRegistry.sol"
BUILD_PATH = BASE / "build" / "FileRegistry.json"

SOLC_VERSION = "0.8.17"   # stable with Ganache UI 2.7.x
EVM_VERSION  = "london"   # match Ganache’s EVM

def main():
    if not (PRIVATE_KEY and ACCOUNT_ADDRESS):
        print("Set PRIVATE_KEY and ACCOUNT_ADDRESS in .env")
        sys.exit(1)
    if not CONTRACT_PATH.exists():
        print("Contract file not found:", CONTRACT_PATH)
        sys.exit(1)

    # --- Compile Solidity for the London EVM ---
    install_solc(SOLC_VERSION)
    source = CONTRACT_PATH.read_text(encoding="utf-8")
    compiled = compile_standard(
        {
            "language": "Solidity",
            "sources": {"FileRegistry.sol": {"content": source}},
            "settings": {
                "optimizer": {"enabled": False, "runs": 200},
                "evmVersion": EVM_VERSION,
                "outputSelection": {"*": {"*": ["abi", "evm.bytecode", "evm.deployedBytecode"]}},
            },
        },
        solc_version=SOLC_VERSION,
    )

    abi = compiled["contracts"]["FileRegistry.sol"]["FileRegistry"]["abi"]
    bytecode = compiled["contracts"]["FileRegistry.sol"]["FileRegistry"]["evm"]["bytecode"]["object"]
    if not bytecode or len(bytecode) < 10:
        print("Compilation produced empty/short bytecode. Check Solidity/EVM settings.")
        sys.exit(1)

    # --- Connect to Ganache & account ---
    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    assert w3.is_connected(), f"Cannot connect to {GANACHE_URL}"

    acct = w3.eth.account.from_key(PRIVATE_KEY)
    assert acct.address.lower() == ACCOUNT_ADDRESS.lower(), "ACCOUNT_ADDRESS does not match PRIVATE_KEY"

    contract = w3.eth.contract(abi=abi, bytecode=bytecode)

    # --- Estimate gas and prepare base tx ---
    try:
        estimated_gas = contract.constructor().estimate_gas({"from": acct.address})
    except Exception:
        estimated_gas = 1_500_000  # safe fallback for this tiny contract
    gas_limit = int(estimated_gas * 1.2)  # +20% safety buffer

    base_tx = {
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "chainId": w3.eth.chain_id,
        "gas": gas_limit,
    }

    # --- Build transaction: try EIP-1559 first, fallback to legacy ---
    use_1559 = True
    try:
        max_fee = w3.to_wei(2, "gwei")
        max_priority = w3.to_wei(1, "gwei")
        construct_txn = contract.constructor().build_transaction({
            **base_tx,
            "maxFeePerGas": max_fee,
            "maxPriorityFeePerGas": max_priority,
        })
        est_cost = gas_limit * max_fee
    except Exception:
        use_1559 = False
        gas_price = w3.to_wei(2, "gwei")
        construct_txn = contract.constructor().build_transaction({
            **base_tx,
            "gasPrice": gas_price,
        })
        est_cost = gas_limit * gas_price

    # --- Balance check before sending ---
    balance = w3.eth.get_balance(acct.address)
    if balance < est_cost:
        def wei_to_eth(x): return x / 10**18
        print("\n❌ Not enough ETH for deployment on this Ganache account.")
        print(f"   Needed (max): ~{wei_to_eth(est_cost):.6f} ETH  |  Available: {wei_to_eth(balance):.6f} ETH")
        print("   Fix: In Ganache, copy a funded account’s Private Key + Address into .env,")
        print("        or Restart Workspace to refill balances, then run again.")
        sys.exit(1)

    # --- Sign and send (with fallback to legacy if node rejects 1559) ---
    signed = acct.sign_transaction(construct_txn)
    try:
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    except Exception:
        if use_1559:
            gas_price = w3.to_wei(2, "gwei")
            legacy_tx = contract.constructor().build_transaction({
                **base_tx,
                "gasPrice": gas_price,
            })
            signed = acct.sign_transaction(legacy_tx)
            tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        else:
            raise

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    deployed_address = receipt["contractAddress"]
    print("Deployed FileRegistry at:", deployed_address)

    # --- Save ABI, bytecode, and address ---
    BUILD_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(BUILD_PATH, "w", encoding="utf-8") as f:
        json.dump({"abi": abi, "bytecode": bytecode, "address": deployed_address}, f, indent=2)

    print("\n✅ Deployment complete!")
    print("Contract deployed at:", deployed_address)


if __name__ == "__main__":
    main()
