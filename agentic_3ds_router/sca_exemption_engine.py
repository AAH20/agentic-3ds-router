"""
PSD2 / PSD3 RTS Strong Customer Authentication (SCA) Exemption Engine.
Calculates regulatory exemption eligibility across Low-Value, Transaction Risk Analysis (TRA),
and FIDO Delegated Authentication tiers to eliminate 3DS challenge friction.
"""

from typing import Tuple
from .models import ThreeDSAuthRequest, SCAExemptionClaim


class SCAExemptionEngine:
    """
    Evaluates regulatory SCA exemption rules under European Banking Authority (EBA) RTS
    and global payment scheme mandates (Visa / Mastercard).
    """

    def __init__(self, acquirer_fraud_rate_bps: float = 4.5):
        # Default: 4.5 bps = 0.045% (well within low-risk tier)
        self.acquirer_fraud_rate_bps = acquirer_fraud_rate_bps

    def evaluate_exemption(self, request: ThreeDSAuthRequest) -> SCAExemptionClaim:
        """
        Determines whether a transaction qualifies for frictionless SCA exemption.
        """
        amt = request.amount

        # Priority 1: Delegated Authentication via FIDO2 Passkey
        if request.has_fido_passkey and request.fido_attestation_data:
            return SCAExemptionClaim(
                exemption_type="DELEGATED_AUTH",
                threshold_limit=10000.0,
                acquirer_fraud_rate_bps=self.acquirer_fraud_rate_bps,
                is_claimable=True,
                rationale="FIDO Alliance / EMVCo 3DS 2.3 Delegated Biometric Authentication Verified"
            )

        # Priority 2: Low-Value Payment Exemption (<= €30 / $30)
        if amt <= 30.0:
            return SCAExemptionClaim(
                exemption_type="LOW_VALUE",
                threshold_limit=30.0,
                acquirer_fraud_rate_bps=self.acquirer_fraud_rate_bps,
                is_claimable=True,
                rationale="Low-value transaction under PSD2/PSD3 EUR 30 regulatory threshold"
            )

        # Priority 3: Acquirer Transaction Risk Analysis (TRA) Exemption Tiers
        # Tier A: Up to 500 if fraud rate <= 1.0 bps (0.01%)
        if amt <= 500.0 and self.acquirer_fraud_rate_bps <= 1.0:
            return SCAExemptionClaim(
                exemption_type="TRA_LOW_RISK",
                threshold_limit=500.0,
                acquirer_fraud_rate_bps=self.acquirer_fraud_rate_bps,
                is_claimable=True,
                rationale=f"TRA Tier 1 (EUR 500): Acquirer fraud rate ({self.acquirer_fraud_rate_bps} bps) <= 1.0 bps"
            )

        # Tier B: Up to 250 if fraud rate <= 6.0 bps (0.06%)
        if amt <= 250.0 and self.acquirer_fraud_rate_bps <= 6.0:
            return SCAExemptionClaim(
                exemption_type="TRA_LOW_RISK",
                threshold_limit=250.0,
                acquirer_fraud_rate_bps=self.acquirer_fraud_rate_bps,
                is_claimable=True,
                rationale=f"TRA Tier 2 (EUR 250): Acquirer fraud rate ({self.acquirer_fraud_rate_bps} bps) <= 6.0 bps"
            )

        # Tier C: Up to 100 if fraud rate <= 13.0 bps (0.13%)
        if amt <= 100.0 and self.acquirer_fraud_rate_bps <= 13.0:
            return SCAExemptionClaim(
                exemption_type="TRA_LOW_RISK",
                threshold_limit=100.0,
                acquirer_fraud_rate_bps=self.acquirer_fraud_rate_bps,
                is_claimable=True,
                rationale=f"TRA Tier 3 (EUR 100): Acquirer fraud rate ({self.acquirer_fraud_rate_bps} bps) <= 13.0 bps"
            )

        return SCAExemptionClaim(
            exemption_type="NONE",
            threshold_limit=0.0,
            acquirer_fraud_rate_bps=self.acquirer_fraud_rate_bps,
            is_claimable=False,
            rationale="Amount exceeds TRA thresholds or acquirer fraud rate too high; Step-up challenge required"
        )
