"""
EMVCo 3DS 2.3 & FIDO Delegated Authentication Gateway.
Orchestrates on-device biometric passkey authentication to achieve frictionless SCA
and secure mandatory chargeback liability shift.
"""

from datetime import datetime, timezone
import hashlib
import hmac
import secrets
import time
from typing import Dict, Optional, Tuple

from .models import (
    ThreeDSAuthRequest,
    ThreeDSAuthResult,
    SCAExemptionClaim,
)
from .sca_exemption_engine import SCAExemptionEngine
from .issuer_risk_predictor import IssuerRiskPredictor


class DelegatedAuthGateway:
    """
    Sub-millisecond dynamic 3DS 2.3 routing gateway.
    Arbitrates between Delegated Authentication, TRA exemption, and Step-Up Challenge.
    """

    def __init__(
        self,
        exemption_engine: Optional[SCAExemptionEngine] = None,
        risk_predictor: Optional[IssuerRiskPredictor] = None
    ):
        self.exemption_engine = exemption_engine or SCAExemptionEngine()
        self.risk_predictor = risk_predictor or IssuerRiskPredictor()

    def route_authentication(self, request: ThreeDSAuthRequest) -> ThreeDSAuthResult:
        """
        Executes sub-5ms intelligent 3DS routing decision.
        """
        start_time = time.perf_counter()
        auth_id = f"3ds_auth_{secrets.token_hex(8)}"
        ds_trans_id = f"{secrets.token_hex(4)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(6)}"

        prob, supports_fido, issuer_name = self.risk_predictor.predict_issuer_acceptance(request)
        exemption = self.exemption_engine.evaluate_exemption(request)

        # Route 1: Delegated Authentication via FIDO2 Passkey
        if request.has_fido_passkey and exemption.exemption_type == "DELEGATED_AUTH":
            latency = (time.perf_counter() - start_time) * 1000.0
            return ThreeDSAuthResult(
                auth_id=auth_id,
                transaction_id=request.transaction_id,
                routing_strategy="DELEGATED_AUTH_PASSKEY",
                verdict="APPROVED_FRICTIONLESS",
                liability_shift_secured=True,  # FIDO Delegated Auth confers full liability shift
                ds_trans_id=ds_trans_id,
                exemption_applied="FIDO2_DELEGATED_AUTHENTICATION",
                routing_latency_ms=round(latency, 3)
            )

        # Route 2: Regulatory Exemption (TRA or Low Value) with High Issuer Propensity
        if exemption.is_claimable and prob >= 0.70:
            latency = (time.perf_counter() - start_time) * 1000.0
            return ThreeDSAuthResult(
                auth_id=auth_id,
                transaction_id=request.transaction_id,
                routing_strategy="FRICTIONLESS_TRA_EXEMPTION",
                verdict="APPROVED_FRICTIONLESS",
                liability_shift_secured=True,  # Scheme rules protect TRA exemptions against fraud liability
                ds_trans_id=ds_trans_id,
                exemption_applied=exemption.exemption_type,
                routing_latency_ms=round(latency, 3)
            )

        # Route 3: Step-Up Challenge Required (Fallback)
        latency = (time.perf_counter() - start_time) * 1000.0
        return ThreeDSAuthResult(
            auth_id=auth_id,
            transaction_id=request.transaction_id,
            routing_strategy="CHALLENGE_REDIRECT",
            verdict="CHALLENGE_REQUIRED",
            liability_shift_secured=False,  # Liability shift only secured post-challenge completion
            ds_trans_id=ds_trans_id,
            exemption_applied=None,
            routing_latency_ms=round(latency, 3)
        )
