"""
Data models and compliance schemas for agentic-3ds-router.
Encodes EMVCo 3DS 2.3 specifications, PSD2/PSD3 RTS Strong Customer Authentication (SCA) exemptions,
and FIDO2 Delegated Authentication cryptograms.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
import time


@dataclass
class ThreeDSAuthRequest:
    """Inbound payment authentication request evaluated by the router."""
    transaction_id: str
    bin_number: str      # First 6 or 8 digits of PAN (e.g., "411111" or "45327100")
    amount: float
    currency: str        # "USD", "EUR", "GBP"
    mcc: str             # e.g., "5734"
    cardholder_ip: str
    device_channel: str  # "BROWSER", "APP", "3RI" (3DS Requestor Initiated)
    has_fido_passkey: bool = False
    fido_attestation_data: Optional[str] = None


@dataclass
class SCAExemptionClaim:
    """Strong Customer Authentication (SCA) exemption asserted under PSD2/PSD3 RTS."""
    exemption_type: str  # "LOW_VALUE", "TRA_LOW_RISK", "DELEGATED_AUTH", "OUT_OF_SCOPE_MIT"
    threshold_limit: float
    acquirer_fraud_rate_bps: float  # Basis points (e.g., 5.0 bps = 0.05%)
    is_claimable: bool
    rationale: str


@dataclass
class ThreeDSAuthResult:
    """Routing and authentication outcome."""
    auth_id: str
    transaction_id: str
    routing_strategy: str  # "DELEGATED_AUTH_PASSKEY", "FRICTIONLESS_TRA_EXEMPTION", "CHALLENGE_REDIRECT"
    verdict: str           # "APPROVED_FRICTIONLESS", "CHALLENGE_REQUIRED", "REJECTED"
    liability_shift_secured: bool  # True: Merchant is protected against fraudulent chargebacks
    ds_trans_id: str       # EMVCo Directory Server Transaction ID
    exemption_applied: Optional[str] = None
    routing_latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class ThreeDSAuditReceipt:
    """Proof sealed to a2zsoc.com Evidence Vault."""
    receipt_id: str
    transaction_id: str
    routing_strategy: str
    verdict: str
    liability_shift: bool
    a2zsoc_merkle_seal: str
    timestamp: float = field(default_factory=time.time)
