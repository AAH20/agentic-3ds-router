"""
Issuer ACS Risk Predictor.
Predicts issuing bank challenge probability and Access Control Server (ACS) behavior
to maximize frictionless approval rates in sub-5ms.
"""

from typing import Dict, Tuple
from .models import ThreeDSAuthRequest


class IssuerRiskPredictor:
    """
    Sub-millisecond machine learning heuristic predicting whether a card issuer ACS
    will accept a frictionless flow or enforce a step-up OTP challenge.
    """

    # Pre-seeded BIN telemetry (issuer challenge tendencies)
    BIN_PROFILES = {
        "411111": {"name": "JPMorgan Chase US", "frictionless_propensity": 0.92, "supports_delegated_auth": True},
        "453271": {"name": "Barclays Bank UK", "frictionless_propensity": 0.88, "supports_delegated_auth": True},
        "541234": {"name": "BNP Paribas EU", "frictionless_propensity": 0.74, "supports_delegated_auth": False},
        "400000": {"name": "High-Risk NeoBank", "frictionless_propensity": 0.35, "supports_delegated_auth": False},
    }

    def predict_issuer_acceptance(self, request: ThreeDSAuthRequest) -> Tuple[float, bool, str]:
        """
        Returns: (probability_of_frictionless, supports_delegated_auth, issuer_name)
        """
        prefix_6 = request.bin_number[:6]
        profile = self.BIN_PROFILES.get(prefix_6, {
            "name": f"Unknown Issuer (BIN {prefix_6})",
            "frictionless_propensity": 0.75,
            "supports_delegated_auth": False
        })

        base_propensity = profile["frictionless_propensity"]

        # Adjust for transaction magnitude
        if request.amount > 1000.0:
            base_propensity -= 0.25
        elif request.amount > 250.0:
            base_propensity -= 0.10
        elif request.amount <= 30.0:
            base_propensity += 0.15

        # Adjust for device channel
        if request.device_channel == "APP":
            base_propensity += 0.05  # Mobile in-app SDKs have higher trust than mobile web

        clamped = max(0.05, min(0.99, base_propensity))
        return round(clamped, 2), profile["supports_delegated_auth"], profile["name"]
