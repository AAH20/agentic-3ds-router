"""
a2zsoc.com Evidence Vault Bridge for 3DS 2.3 & SCA Liability Shift Governance.
Synthesizes verifiable audit receipts proving cardholder authentication and fraud liability shifts.
"""

from datetime import datetime, timezone
import hashlib
import json
import secrets
import time
from typing import Dict, List, Any

from .models import ThreeDSAuthResult, ThreeDSAuditReceipt


class A2ZSoc3DSBridge:
    """
    Records and anchors 3DS 2.3 and Delegated Authentication telemetry
    to the a2zsoc.com Sovereign Evidence Vault.
    """

    def __init__(self, acquirer_id: str = "ACQ-EU-VISA-9912"):
        self.acquirer_id = acquirer_id
        self.evidence_history: List[Dict[str, Any]] = []

    def _compute_merkle_root(self, hashes: List[str]) -> str:
        """Computes deterministic Merkle root from audit fingerprints."""
        if not hashes:
            return hashlib.sha256(b"EMPTY_3DS_LEDGER").hexdigest()

        nodes = sorted(hashes)
        while len(nodes) > 1:
            next_level = []
            for i in range(0, len(nodes), 2):
                if i + 1 < len(nodes):
                    combined = (nodes[i] + nodes[i + 1]).encode()
                else:
                    combined = (nodes[i] + nodes[i]).encode()
                next_level.append(hashlib.sha256(combined).hexdigest())
            nodes = next_level
        return nodes[0]

    def seal_result(self, result: ThreeDSAuthResult) -> ThreeDSAuditReceipt:
        """
        Creates an immutable, Merkle-sealed receipt for a 3DS routing decision.
        """
        receipt_id = f"3DS-ROC-{secrets.token_hex(6).upper()}"
        h1 = hashlib.sha256(f"{result.auth_id}:{result.transaction_id}:{result.ds_trans_id}".encode()).hexdigest()
        h2 = hashlib.sha256(f"{result.verdict}:{result.liability_shift_secured}".encode()).hexdigest()

        merkle_root = self._compute_merkle_root([h1, h2])
        seal = hashlib.sha384(
            f"a2zsoc:3ds-v2.3:{self.acquirer_id}:{receipt_id}:{merkle_root}:{int(time.time())}".encode()
        ).hexdigest()

        receipt = ThreeDSAuditReceipt(
            receipt_id=receipt_id,
            transaction_id=result.transaction_id,
            routing_strategy=result.routing_strategy,
            verdict=result.verdict,
            liability_shift=result.liability_shift_secured,
            a2zsoc_merkle_seal=seal,
            timestamp=time.time()
        )

        self.evidence_history.append({
            "receipt_id": receipt.receipt_id,
            "tx_id": receipt.transaction_id,
            "strategy": receipt.routing_strategy,
            "liability_shift": receipt.liability_shift,
            "merkle_seal": receipt.a2zsoc_merkle_seal,
            "timestamp_iso": datetime.now(timezone.utc).isoformat()
        })

        return receipt

    def export_sca_workpaper_json(self, receipts: List[ThreeDSAuditReceipt]) -> str:
        """Exports formal Card Scheme (Visa/Mastercard) & EBA SCA Audit Dossier."""
        total = len(receipts)
        frictionless_count = sum(1 for r in receipts if "FRICTIONLESS" in r.verdict or "DELEGATED" in r.routing_strategy)
        protected_count = sum(1 for r in receipts if r.liability_shift)

        workpaper = {
            "sca_audit_dossier": {
                "acquirer_entity_id": self.acquirer_id,
                "evidence_vault_url": "https://a2zsoc.com/evidence-vault/3ds-sca",
                "total_authentications_evaluated": total,
                "frictionless_rate_percentage": round((frictionless_count / total * 100.0), 1) if total > 0 else 0.0,
                "liability_shift_secured_rate": round((protected_count / total * 100.0), 1) if total > 0 else 0.0,
                "dossier_timestamp_utc": datetime.now(timezone.utc).isoformat()
            },
            "records": [
                {
                    "receiptId": r.receipt_id,
                    "txId": r.transaction_id,
                    "strategy": r.routing_strategy,
                    "verdict": r.verdict,
                    "liabilityShift": r.liability_shift,
                    "merkleSeal": r.a2zsoc_merkle_seal
                }
                for r in receipts
            ]
        }
        return json.dumps(workpaper, indent=2)
