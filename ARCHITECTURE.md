# ARCHITECTURE & DESIGN DOCUMENTATION

## 1. SMTP Security Gateway vs. Connected-Mailbox Ingestion

TraceMail AI implements a dual-ingestion architecture designed to address both enterprise perimeter security and continuous cloud mailbox monitoring:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. PRE-DELIVERY ENFORCEMENT (TraceMail SMTP Security Gateway)               │
│                                                                             │
│   Internet Inbound Email                                                    │
│          │                                                                  │
│          ▼                                                                  │
│   ┌───────────────┐                                                         │
│   │ Organization  │ (Configured MX Record / Inbound Routing Rule)           │
│   │ MX Inbound    │                                                         │
│   └──────┬────────┘                                                         │
│          │                                                                  │
│          ▼                                                                  │
│   ┌───────────────────────────────────────────────────────────┐             │
│   │ TraceMail Inbound SMTP Gateway (Port 1025)                │             │
│   │  • Immutable SHA-256 Evidence Preservation                │             │
│   │  • Fast Sentinel Screening (<2ms)                         │             │
│   │  • Deep ML / BEC Threat Engine                            │             │
│   │  • Relay Path Reconstruction & Origin Geolocation         │             │
│   │  • Evidence Fusion Decision                               │             │
│   └──────┬────────────────────────────────────────────┬───────┘             │
│          │                                            │                     │
│     [SAFE / WARN]                             [HIGH / CRITICAL]             │
│          │                                            │                     │
│          ▼                                            ▼                     │
│   ┌───────────────┐                           ┌───────────────┐             │
│   │ Downstream    │                           │ Pre-Delivery  │             │
│   │ Mailbox Server│                           │ Quarantine    │             │
│   │ (Port 1026)   │                           │ (Held in TM)  │             │
│   └───────────────┘                           └───────────────┘             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. POST-ARRIVAL MONITORING (Connected-Mailbox API / Connectors)              │
│                                                                             │
│   • Google Workspace / Gmail API (users.watch + Pub/Sub / Delta Sync)       │
│   • Microsoft 365 / Graph API (Graph Webhook Notifications)                 │
│   • Yahoo / Generic IMAP (Authorized IMAP IDLE & Polling)                   │
│                                                                             │
│   * Used for secondary auditing, retrospective rescanning, & internal mail  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Important Production Deployment Reality
- **Consumer Gmail Accounts**: A consumer `@gmail.com` address cannot have a 3rd party SMTP gateway inserted before Google's MX infrastructure.
- **Enterprise Pre-Delivery Enforcement**: Requires an organization-owned custom domain (e.g. `example.com`), with DNS MX records or Google Workspace / Microsoft 365 Inbound Gateway Routing configured to relay mail through TraceMail before final delivery.

---

## 2. Threat Classification & The "SPF PASS != SAFE" Axiom

Traditional email filters fail on Business Email Compromise (BEC) and compromised account takeovers because attackers send emails through legitimate, authenticated infrastructure (SPF=PASS, DKIM=PASS).

TraceMail AI's **RuleAndNLPThreatEngine** decouples cryptographic authenticity from behavioral intent:
1. **Cryptographic Authentication**: Verifies the envelope was authorized by the sending domain.
2. **Behavioral Evaluation**: Detects executive pressure, bank account routing modifications, invoice payment lures, and credential harvesting intents.
3. **Corroborating Synergy**: Authenticated BEC triggers elevated risk scores rather than being masked as benign.

---

## 3. Probable Observable Infrastructure vs "Hacker Location"

TraceMail AI enforces strict cybersecurity accuracy:
- **No False Attribution**: Geolocation derived from IP hops reveals only the *Probable Observable Infrastructure* (e.g., hosting datacenter, commercial VPN, or TOR node).
- **Dual Metric Separation**:
  - **Threat Risk Score (0-100)**: Reflects the malicious intent and payload danger.
  - **Origin Confidence (0-100)**: Reflects the reliability of the reconstructed relay trail (reduced by TOR, VPNs, cloud transit, or single-hop masking).

---

## 4. Tamper-Evident Hash-Chained Audit Trail

Audit records in TraceMail AI are cryptographically linked using SHA-256 hash chaining:
$$\text{EventHash}_n = \text{SHA256}(\text{EventHash}_{n-1} + \text{EventType} + \text{Actor} + \text{Resource} + \text{Payload} + \text{Timestamp})$$

Any direct alteration to historic database records breaks the cryptographic verification chain immediately.
