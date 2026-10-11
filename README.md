# Agentic-3DS-Router

**3DS 2.3 & Delegated Authentication SCA Decisioning Engine for Payment Gateways (PSD2 / PSD3 RTS) — reference implementation**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![EMVCo 3DS 2.3](https://img.shields.io/badge/EMVCo-3DS%202.3%20(decisioning%20model)-green.svg)](https://www.emvco.com/)
[![FIDO2 Delegated Auth](https://img.shields.io/badge/FIDO2-Delegated%20Auth%20(modeled)-purple.svg)](https://fidoalliance.org/)
[![PSD3 TRA Exemption](https://img.shields.io/badge/PSD3%20RTS-TRA%20Exemptions%20(rules)-blue.svg)](https://www.eba.europa.eu/)
[![Evidence Seal](https://img.shields.io/badge/Evidence%20Seal-local%20SHA--384-teal.svg)](https://a2zsoc.com)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-yellow.svg)](LICENSE)

---

## Executive Summary: Slicing the 22% Checkout Abandonment Barrier

Strong Customer Authentication (SCA) under European PSD2/PSD3 and global card scheme regulations protects against card-not-present fraud, but introduces catastrophic checkout friction. **22% to 28% of consumers abandon checkout** when redirected to clunky bank iframes or forced to wait for cellular SMS one-time passcodes (OTPs):

1. **SMS OTP Vulnerabilities & Friction**:  
   SMS OTPs are vulnerable to SIM-swap attacks and adversary-in-the-middle (AiTM) phishing proxies, while cellular latency causes high shopping cart drop-offs.
2. **The FIDO2 Delegated Authentication Revolution**:  
   Under **EMVCo 3DS 2.3** and the **FIDO Alliance Delegated Authentication** framework, card issuers allow certified merchants and payment gateways to authenticate consumers via **on-device biometric passkeys (Face ID, Touch ID, Windows Hello)**, completely bypassing the issuer challenge iframe while securing full **fraud liability shift**.
3. **The PSD2 / PSD3 Transaction Risk Analysis (TRA) Arbitrage**:  
   Regulatory technical standards permit frictionless exemption for low-risk transactions (up to €500 depending on acquirer fraud rate). However, acquirers lacking real-time issuer intelligence frequently trigger "soft declines" from conservative issuer Access Control Servers (ACS).

`agentic-3ds-router` addresses this with a lightweight, dependency-free decisioning engine: it applies rule-based SCA exemption logic (Low-Value, TRA, or Delegated Auth) plus a heuristic issuer-propensity lookup to choose a routing strategy, then seals each decision locally with a SHA-384 Merkle receipt.

> **Implementation status — what this repository actually contains.** The open-source core is a pure-Python (standard-library only) **rule-based SCA exemption + routing decision engine** that produces a **local SHA-384 Merkle receipt**. It does **not** implement the live EMVCo 3DS network protocol (no Directory Server or ACS connection), does **not** perform RFC 3161 trusted timestamping, and contains **no machine-learning model**. It is a deterministic reference implementation of the decisioning logic, not a certified 3DS Server. Live scheme connectivity, RFC 3161 timestamping, and BIN machine learning are **roadmap** items, not shipped features.

---

## System Architecture

```mermaid
flowchart TD
    subgraph ClientDOM["Consumer Checkout Interface"]
        UserBrowser["Shopper Browser / Mobile App"]
        FIDO2Passkey["On-Device Biometric Passkey (WebAuthn)"]
    end

    subgraph DynamicRouter["Agentic 3DS 2.3 Routing Gateway"]
        AuthReceiver["Inbound Payment Auth Request"]
        SCAEngine["PSD2 / PSD3 SCA Exemption Engine"]
        RiskPredictor["Heuristic Issuer Propensity Lookup"]
        DelegatedGateway["FIDO Delegated Authentication Gateway"]
    end

    subgraph CardSchemeDirectory["EMVCo 3DS Directory Server & Issuers"]
        SchemeDS["Visa / Mastercard Directory Server (3DS 2.3)"]
        IssuerACS["Issuing Bank Access Control Server (ACS)"]
    end

    subgraph EvidenceVaultBridge["Continuous Compliance & a2zsoc.com Vault"]
        LiabilityRecorder["Liability Shift & CAVV/AAV Recorder"]
        MerkleSealer["Local SHA-384 Merkle Sealer"]
        A2ZSocVault["a2zsoc.com Sovereign Evidence Vault"]
    end

    UserBrowser -->|1. Auth Request ($180.00)| AuthReceiver
    AuthReceiver --> SCAEngine
    AuthReceiver --> RiskPredictor

    SCAEngine -->|Evaluate Amount vs Acquirer Fraud Rate| DelegatedGateway
    RiskPredictor -->|Forecast Issuer BIN Propensity| DelegatedGateway

    alt Passkey Available & Supported
        DelegatedGateway -->|2a. Invoke Delegated Biometrics| FIDO2Passkey
        FIDO2Passkey -->|3a. Signed Attestation Cryptogram| DelegatedGateway
        DelegatedGateway -->|4a. 3DS 2.3 Delegated Auth Payload| SchemeDS
        SchemeDS -->|5a. Frictionless Approval (Liability Shift = True)| UserBrowser
    else Qualified TRA Exemption & High Issuer Propensity
        DelegatedGateway -->|4b. Assert TRA Exemption Flag| SchemeDS
        SchemeDS -->|5b. Direct Auth Approval (No Challenge)| UserBrowser
    else High Risk / Challenge Required
        DelegatedGateway -->|4c. Step-Up Challenge Redirect| IssuerACS
        IssuerACS -->|5c. Render Challenge Screen| UserBrowser
    end

    DelegatedGateway -->|6. Log Decision Telemetry| LiabilityRecorder
    LiabilityRecorder -->|7. Compute Merkle Root| MerkleSealer
    MerkleSealer -->|8. Seal Attestation to Vault| A2ZSocVault
```

> *Note: the scheme Directory Server (Visa/Mastercard DS) and Issuer ACS hops above depict the target integration. The OSS core performs no network exchange — it produces a local routing decision and a local SHA-384 Merkle seal only.*

---

## Detailed Subsystem Blueprints

### 1. PSD2 / PSD3 RTS SCA Exemption Engine (`sca_exemption_engine.py`)
- **Regulatory Framework**: EBA Regulatory Technical Standards (RTS) on Strong Customer Authentication.
- **Exemption Tiers**:
  - **Low-Value Exemption**: Transactions $\le$ €30 / $30.
  - **TRA Tier 1**: Transactions $\le$ €500 if acquirer fraud rate $\le$ 1.0 bps (0.01%).
  - **TRA Tier 2**: Transactions $\le$ €250 if acquirer fraud rate $\le$ 6.0 bps (0.06%).
  - **TRA Tier 3**: Transactions $\le$ €100 if acquirer fraud rate $\le$ 13.0 bps (0.13%).
  - **Delegated Authentication**: Transactions authorized via biometric passkeys.

### 2. Issuer ACS Risk Predictor (`issuer_risk_predictor.py`)
- A **heuristic lookup, not a trained model**: it returns a base frictionless-propensity value from a small hardcoded table of four issuer BIN profiles, defaulting to 0.75 for unknown BINs.
- Adjusts that base value with fixed additive rules for transaction magnitude and device channel (mobile in-app vs. web). It uses no historical BIN data, live telemetry, or learned parameters.

### 3. Delegated Authentication Gateway (`delegated_auth_gateway.py`)
- Sequence Flow:
  ```mermaid
  sequenceDiagram
      autonumber
      participant App as Checkout Application
      participant Router as 3DS Dynamic Router
      participant FIDO as On-Device FIDO2 Passkey
      participant DS as Card Network DS (Visa/MC)
      participant ACS as Issuer Bank ACS

      App->>Router: Submit Auth (Amount: $450, Card: 453271)
      Router->>Router: Predict ACS Propensity & Check Passkey Support
      Router->>FIDO: Request WebAuthn Assertion
      FIDO-->>Router: Biometric Cryptogram Assertion
      Router->>DS: 3DS 2.3 AReq (Delegated Auth Flag + Cryptogram)
      DS->>ACS: Validate Cryptogram
      ACS-->>DS: ARes (Frictionless Approved, TransStatus: Y)
      DS-->>Router: Cavv / ECI 05 (Full Liability Shift)
      Router-->>App: Frictionless Success (Zero Redirect)
  ```

  *Note: this sequence shows the intended end-to-end flow. The OSS core stops after computing the local routing decision and receipt; the DS/ACS validation steps are roadmap.*

### 4. a2zsoc.com Evidence Vault Bridge (`a2zsoc_3ds_bridge.py`)
- Builds a local audit receipt from the routing result: transaction ID, routing strategy, verdict, liability-shift flag, and a locally generated `dsTransID` (a random identifier — it is **not** obtained from a live Directory Server).
- Computes a SHA-256 Merkle root over the receipt hashes and a **local SHA-384 seal** over the receipt fields. Nothing is transmitted to a2zsoc.com, and no RFC 3161 timestamp authority is used — the "seal" is a local digest.

---

## OSS Core vs. Enterprise Commercial Layer

| Capability | Open-Source Core (`agentic-3ds-router`) | Enterprise Sovereign Layer (`a2zsoc.com`) |
| :--- | :--- | :--- |
| **EMVCo Protocol** | Local routing-decision model; no AReq/ARes network exchange (roadmap) | Direct certified EMVCo 3DS Server connection to Visa, Mastercard, Amex, Discover |
| **Issuer BIN Telemetry** | Local heuristic lookup over four hardcoded issuer BIN profiles | Real-time AI model updating across 40,000+ global BINs with live soft-decline tracking |
| **Delegated Auth** | Checks a caller-supplied passkey flag + attestation string; does not parse/verify WebAuthn (roadmap) | Fully hosted Passkey SDK for iOS, Android, and Web with bi-directional issuer enrollment |
| **Liability Shift Audit** | Local SHA-384 Merkle receipt + JSON workpaper export (no RFC 3161, no network) | Continuous automated evidence submission directly to card network dispute portals |

---

## Illustrative Targets (not benchmarked in this repository)

> **These numbers are aspirational targets, not measured results.** This repository ships no benchmark harness, load generator, or checkout dataset, so none of the figures below have been measured for `agentic-3ds-router`.

| Target Metric | Traditional 3DS 1.0 / 2.1 (SMS OTP) | Naive TRA Gateway | `agentic-3ds-router` (target) |
| :--- | :--- | :--- | :--- |
| **Checkout Abandonment** | **22.4%** (High friction) | 14.2% | **3.8% (Frictionless Passkey/TRA)** |
| **Decision Routing Latency** | 1,800 ms (Redirect load) | 120 ms | **0.25 ms (In-Memory Engine)** |
| **Frictionless Approval Rate**| 38% | 61% | **84% (Passkey + TRA Arbitrage)** |
| **Liability Shift Protection**| Partial (Lost on soft decline)| Fragile | **100% Guaranteed on Approved Flows** |
| **External Dependencies** | Heavy (Proprietary SDKs) | Moderate | **Zero (Standard Library Only)** |

---

## Quickstart & CLI Usage

```bash
git clone https://github.com/AAH20/agentic-3ds-router.git
cd agentic-3ds-router
python3 -m unittest discover -s tests -v
```

### Run Full 4-Case Routing Demonstration
```bash
python3 -m agentic_3ds_router.cli --demo
```

### Export Formal SCA Workpaper JSON
```bash
python3 -m agentic_3ds_router.cli --export-workpaper
```

---

## Contributing & License

Contributions adhering to EMVCo 3DS 2.3 and FIDO Alliance specifications are welcome. Licensed under the [Apache License, Version 2.0](LICENSE).
