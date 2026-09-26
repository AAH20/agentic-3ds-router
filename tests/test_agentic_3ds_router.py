"""
Unit Test Suite for Agentic 3DS Router.
Validates SCA exemption calculations, issuer risk prediction, FIDO Delegated Auth, and liability shifts.
"""

import json
import unittest

from agentic_3ds_router.models import (
    ThreeDSAuthRequest,
    ThreeDSAuthResult,
    SCAExemptionClaim,
    ThreeDSAuditReceipt,
)
from agentic_3ds_router.sca_exemption_engine import SCAExemptionEngine
from agentic_3ds_router.issuer_risk_predictor import IssuerRiskPredictor
from agentic_3ds_router.delegated_auth_gateway import DelegatedAuthGateway
from agentic_3ds_router.a2zsoc_3ds_bridge import A2ZSoc3DSBridge


class TestSCAExemptionEngine(unittest.TestCase):
    def setUp(self):
        self.engine = SCAExemptionEngine(acquirer_fraud_rate_bps=4.5)

    def test_low_value_exemption(self):
        req = ThreeDSAuthRequest("tx_1", "411111", 28.50, "USD", "5812", "1.1.1.1", "BROWSER")
        claim = self.engine.evaluate_exemption(req)
        self.assertTrue(claim.is_claimable)
        self.assertEqual(claim.exemption_type, "LOW_VALUE")

    def test_tra_tier_exemption(self):
        req = ThreeDSAuthRequest("tx_2", "411111", 220.00, "USD", "5311", "1.1.1.1", "BROWSER")
        claim = self.engine.evaluate_exemption(req)
        self.assertTrue(claim.is_claimable)
        self.assertEqual(claim.exemption_type, "TRA_LOW_RISK")

    def test_delegated_auth_priority(self):
        req = ThreeDSAuthRequest(
            "tx_3", "411111", 1500.00, "USD", "5732", "1.1.1.1", "APP",
            has_fido_passkey=True, fido_attestation_data="yubikey_assertion"
        )
        claim = self.engine.evaluate_exemption(req)
        self.assertTrue(claim.is_claimable)
        self.assertEqual(claim.exemption_type, "DELEGATED_AUTH")


class TestIssuerRiskPredictor(unittest.TestCase):
    def setUp(self):
        self.predictor = IssuerRiskPredictor()

    def test_chase_bin_high_propensity(self):
        req = ThreeDSAuthRequest("tx_1", "411111", 50.0, "USD", "5411", "1.1.1.1", "BROWSER")
        prob, supports_fido, name = self.predictor.predict_issuer_acceptance(req)
        self.assertGreaterEqual(prob, 0.85)
        self.assertTrue(supports_fido)
        self.assertIn("JPMorgan Chase", name)

    def test_high_risk_bin_low_propensity(self):
        req = ThreeDSAuthRequest("tx_2", "400000", 1500.0, "USD", "6012", "1.1.1.1", "BROWSER")
        prob, _, _ = self.predictor.predict_issuer_acceptance(req)
        self.assertLess(prob, 0.40)


class TestDelegatedAuthGateway(unittest.TestCase):
    def setUp(self):
        self.gateway = DelegatedAuthGateway()

    def test_delegated_auth_flow(self):
        req = ThreeDSAuthRequest(
            "tx_fido", "453271", 350.0, "USD", "5734", "1.1.1.1", "APP",
            has_fido_passkey=True, fido_attestation_data="token_data"
        )
        result = self.gateway.route_authentication(req)
        self.assertEqual(result.routing_strategy, "DELEGATED_AUTH_PASSKEY")
        self.assertEqual(result.verdict, "APPROVED_FRICTIONLESS")
        self.assertTrue(result.liability_shift_secured)
        self.assertLess(result.routing_latency_ms, 5.0)

    def test_tra_flow(self):
        req = ThreeDSAuthRequest("tx_tra", "411111", 90.0, "USD", "5812", "1.1.1.1", "BROWSER")
        result = self.gateway.route_authentication(req)
        self.assertEqual(result.routing_strategy, "FRICTIONLESS_TRA_EXEMPTION")
        self.assertEqual(result.verdict, "APPROVED_FRICTIONLESS")
        self.assertTrue(result.liability_shift_secured)

    def test_challenge_fallback_flow(self):
        req = ThreeDSAuthRequest("tx_chal", "400000", 3000.0, "USD", "6012", "1.1.1.1", "BROWSER")
        result = self.gateway.route_authentication(req)
        self.assertEqual(result.routing_strategy, "CHALLENGE_REDIRECT")
        self.assertEqual(result.verdict, "CHALLENGE_REQUIRED")
        self.assertFalse(result.liability_shift_secured)


class TestA2ZSoc3DSBridge(unittest.TestCase):
    def setUp(self):
        self.bridge = A2ZSoc3DSBridge()
        self.gateway = DelegatedAuthGateway()

    def test_seal_and_export(self):
        req = ThreeDSAuthRequest("tx_audit", "411111", 15.0, "USD", "5812", "1.1.1.1", "BROWSER")
        res = self.gateway.route_authentication(req)
        receipt = self.bridge.seal_result(res)

        self.assertTrue(receipt.liability_shift)
        self.assertTrue(len(receipt.a2zsoc_merkle_seal) > 30)

        workpaper = self.bridge.export_sca_workpaper_json([receipt])
        data = json.loads(workpaper)
        self.assertEqual(data["sca_audit_dossier"]["frictionless_rate_percentage"], 100.0)


if __name__ == "__main__":
    unittest.main()
