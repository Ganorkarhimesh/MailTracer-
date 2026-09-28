"""
MailTracer-AI :: Optional Forensic Log Anchoring (Testnet)
-----------------------------------------------------------
Writes a SHA-256 hash of each analysis result to a public testnet
(e.g. Sepolia) as an immutable forensic audit trail, so investigators
can later prove a report was not altered after the fact.

This is OPTIONAL and controlled by BLOCKCHAIN_LOGGING_ENABLED. Without
a configured RPC endpoint + wallet key, it returns a local-only
"simulated" receipt so the rest of the platform still works offline.

Dependencies: web3 (optional)
"""

from __future__ import annotations

import os
import json
import hashlib
import time
from dataclasses import dataclass, asdict
from typing import Optional

try:
    from web3 import Web3
except ImportError:  # pragma: no cover
    Web3 = None

BLOCKCHAIN_LOGGING_ENABLED = os.getenv("BLOCKCHAIN_LOGGING_ENABLED", "false").lower() == "true"
TESTNET_RPC_URL = os.getenv("TESTNET_RPC_URL", "")
WALLET_PRIVATE_KEY = os.getenv("WALLET_PRIVATE_KEY", "")
LOG_CONTRACT_ADDRESS = os.getenv("LOG_CONTRACT_ADDRESS", "")


@dataclass
class BlockchainReceipt:
    enabled: bool
    report_hash: str
    tx_hash: Optional[str] = None
    network: Optional[str] = None
    timestamp: float = 0.0
    mode: str = "simulated"  # "onchain" or "simulated"


def _hash_report(report: dict) -> str:
    canonical = json.dumps(report, sort_keys=True, default=str).encode("utf-8")
    return "0x" + hashlib.sha256(canonical).hexdigest()


def anchor_report(report: dict) -> BlockchainReceipt:
    """Hashes the analysis report and optionally writes it to a testnet chain."""
    report_hash = _hash_report(report)
    ts = time.time()

    if not BLOCKCHAIN_LOGGING_ENABLED:
        return BlockchainReceipt(enabled=False, report_hash=report_hash, timestamp=ts, mode="simulated")

    if Web3 is None or not TESTNET_RPC_URL or not WALLET_PRIVATE_KEY:
        # Degrade gracefully instead of failing the whole analysis request
        return BlockchainReceipt(enabled=True, report_hash=report_hash, timestamp=ts, mode="simulated")

    try:
        w3 = Web3(Web3.HTTPProvider(TESTNET_RPC_URL))
        account = w3.eth.account.from_key(WALLET_PRIVATE_KEY)
        tx = {
            "from": account.address,
            "to": account.address,  # self-send carrying the hash in `data`
            "value": 0,
            "gas": 30000,
            "gasPrice": w3.eth.gas_price,
            "nonce": w3.eth.get_transaction_count(account.address),
            "data": report_hash,
            "chainId": w3.eth.chain_id,
        }
        signed = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        return BlockchainReceipt(
            enabled=True,
            report_hash=report_hash,
            tx_hash=tx_hash.hex(),
            network=str(w3.eth.chain_id),
            timestamp=ts,
            mode="onchain",
        )
    except Exception:
        return BlockchainReceipt(enabled=True, report_hash=report_hash, timestamp=ts, mode="simulated")


def receipt_to_dict(receipt: BlockchainReceipt) -> dict:
    return asdict(receipt)
