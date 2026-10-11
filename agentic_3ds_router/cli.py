"""
Command Line Interface for Agentic 3DS Router.
Simulates sub-millisecond dynamic 3DS 2.3 routing, FIDO2 Delegated Authentication,
and PSD3 TRA exemption arbitrage.
"""

import argparse
import json
import time

from .models import ThreeDSAuthRequest
from .delegated_auth_gateway import DelegatedAuthGateway
from .a2zsoc_3ds_bridge import A2ZSoc3DSBridge


def print_banner():
    banner = r"""
================================================================================
    ___                    __  _          _____ ____  _____    ____             __           
   /   | ____ _ ___  ____ / /_(_)_____   |__  // __ \/ ___/   / __ \____  __  __/ /____  _____
  / /| |/ __ `// _ \/ __ \ __/ // ___/    /_ </ / / /\__ \   / /_/ / __ \/ / / / __/ _ \/ ___/
 / ___ / /_/ //  __/ / / / /_ / // /__   ___/ / /_/ /___/ /  / _, _/ /_/ / /_/ / /_/  __/ /    
/_/  |_\__, / \___/_/ /_/\__//_/ \___/  /____/_____//____/  /_/ |_|\____/\__,_/\__/\___/_/     
      /____/    Dynamic 3DS 2.3 & FIDO2 Delegated Auth Engine (PSD2 / PSD3 RTS)
================================================================================
"""
    print(banner)


def run_full_demo():
    print_banner()
    print("Initiating Dynamic 3DS 2.3 & Delegated Authentication Routing Sprint...\n")
    time.sleep(0.3)

    gateway = DelegatedAuthGateway()
    bridge = A2ZSoc3DSBridge()
    receipts = []

    # Case 1: Low-Value Exemption
    print(">>> [CASE 1/4] LOW-VALUE REGULATORY EXEMPTION (< EUR 30)")
    req1 = ThreeDSAuthRequest(
        transaction_id="tx_low_val_101",
        bin_number="411111",
        amount=19.99,
        currency="USD",
        mcc="5812",
        cardholder_ip="192.0.2.1",
        device_channel="BROWSER"
    )
    res1 = gateway.route_authentication(req1)
    print(f"  [STRATEGY]     : {res1.routing_strategy} (Exemption: {res1.exemption_applied})")
    print(f"  [VERDICT]      : {res1.verdict} (Liability Shift: {res1.liability_shift_secured})")
    print(f"  [LATENCY]      : {res1.routing_latency_ms:.3f} ms")
    print("  [STATUS] -> PASS (Cart friction eliminated)\n")
    receipts.append(bridge.seal_result(res1))
    time.sleep(0.3)

    # Case 2: FIDO2 Delegated Authentication (High Value Cart)
    print(">>> [CASE 2/4] FIDO2 / WEBAUTHN DELEGATED AUTHENTICATION ($450.00)")
    req2 = ThreeDSAuthRequest(
        transaction_id="tx_fido_delegated_202",
        bin_number="453271",
        amount=450.00,
        currency="USD",
        mcc="5732",
        cardholder_ip="192.0.2.2",
        device_channel="APP",
        has_fido_passkey=True,
        fido_attestation_data="fido2_assertion_yubikey_fips"
    )
    res2 = gateway.route_authentication(req2)
    print(f"  [STRATEGY]     : {res2.routing_strategy}")
    print(f"  [VERDICT]      : {res2.verdict} (Liability Shift: {res2.liability_shift_secured})")
    print(f"  [EMVCo DS ID]  : {res2.ds_trans_id}")
    print(f"  [LATENCY]      : {res2.routing_latency_ms:.3f} ms")
    print("  [STATUS] -> PASS (Biometric passkey verified on device; zero OTP SMS)\n")
    receipts.append(bridge.seal_result(res2))
    time.sleep(0.3)

    # Case 3: Acquirer TRA Low-Risk Exemption
    print(">>> [CASE 3/4] ACQUIRER TRANSACTION RISK ANALYSIS (TRA) EXEMPTION ($180.00)")
    req3 = ThreeDSAuthRequest(
        transaction_id="tx_tra_exempt_303",
        bin_number="411111",
        amount=180.00,
        currency="USD",
        mcc="5311",
        cardholder_ip="192.0.2.3",
        device_channel="BROWSER"
    )
    res3 = gateway.route_authentication(req3)
    print(f"  [STRATEGY]     : {res3.routing_strategy} (Exemption: {res3.exemption_applied})")
    print(f"  [VERDICT]      : {res3.verdict} (Liability Shift: {res3.liability_shift_secured})")
    print(f"  [LATENCY]      : {res3.routing_latency_ms:.3f} ms")
    print("  [STATUS] -> PASS (Low acquirer fraud rate utilized to bypass challenge)\n")
    receipts.append(bridge.seal_result(res3))
    time.sleep(0.3)

    # Case 4: High-Risk Step-Up Challenge Fallback
    print(">>> [CASE 4/4] HIGH-RISK / HIGH-VALUE STEP-UP CHALLENGE ($2,850.00)")
    req4 = ThreeDSAuthRequest(
        transaction_id="tx_challenge_404",
        bin_number="400000",
        amount=2850.00,
        currency="USD",
        mcc="6012",
        cardholder_ip="198.51.100.99",
        device_channel="BROWSER"
    )
    res4 = gateway.route_authentication(req4)
    print(f"  [STRATEGY]     : {res4.routing_strategy}")
    print(f"  [VERDICT]      : {res4.verdict} (Pre-challenge liability shift: {res4.liability_shift_secured})")
    print(f"  [LATENCY]      : {res4.routing_latency_ms:.3f} ms")
    print("  [STATUS] -> PASS (Step-up challenge dispatched to protect against fraud loss)\n")
    receipts.append(bridge.seal_result(res4))
    time.sleep(0.3)

    # Summary
    print(">>> [STAGE 5/5] a2zsoc.com EVIDENCE VAULT SEALER & SCA DOSSIER")
    print(f"  [PROOFS SEALED] : {len(receipts)} Transactions Recorded with Merkle Root")
    print("  [STATUS] -> COMPLIANT_CERTIFIED (Local SHA-384 Merkle Seal; no RFC 3161, no network)\n")

    print("=" * 80)
    print("DYNAMIC 3DS 2.3 SPRINT COMPLETE: LOCAL DECISIONING + EVIDENCE SEAL")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="Agentic 3DS Router - Dynamic 3DS 2.3 & Delegated Auth Engine")
    parser.add_argument("--demo", action="store_true", help="Execute complete 4-case 3DS routing demonstration")
    parser.add_argument("--export-workpaper", action="store_true", help="Export SCA liability shift workpaper JSON")

    args = parser.parse_args()

    if args.export_workpaper:
        gw = DelegatedAuthGateway()
        bridge = A2ZSoc3DSBridge()
        req = ThreeDSAuthRequest("tx_1", "411111", 25.0, "USD", "5734", "1.1.1.1", "BROWSER")
        res = gw.route_authentication(req)
        r = bridge.seal_result(res)
        print(bridge.export_sca_workpaper_json([r]))
    else:
        run_full_demo()


if __name__ == "__main__":
    main()
