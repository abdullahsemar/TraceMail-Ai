# TraceMail AI — Architectural Specification

## Research-Grounded Non-Quarantining Pre-Delivery SMTP Security Proxy & Forensic Platform

```text
                        EMAIL SOURCES

              ┌──────────────┴──────────────┐
              ▼                             ▼
         SMTP PROXY                   Gmail/API/.EML
       (Inbound 1025)             (Retrospective Ingestion)
              │                             │
              └──────────────┬──────────────┘
                             ▼
                     RAW RFC822 / MIME
                             ▼
                    SHA-256 PRESERVATION
                    (Immutable Forensics)
                             ▼
           ┌─────────────────────────────────────┐
           │         FORENSIC ENGINES            │
           │                                     │
           │ 1. Authentication (SPF/DKIM/DMARC)  │
           │ 2. Identity (Name Norm & Spoofing)  │
           │ 3. Behavioral Intelligence (Cidon)  │
           │ 4. Transformer Content (DistilBERT) │
           │ 5. URL / Domain Intelligence (RDAP) │
           │ 6. Attachment Forensics (SHA-256)   │
           │ 7. Relay & Observable Infrastructure│
           │ 8. Threat Intelligence Enrichment   │
           │ 9. Fuzzy Campaign Similarity (SimHash)│
           └────────────────┬────────────────────┘
                            ▼
                 STANDARDIZED EVIDENCE V2
            (Engine, Type, Direction, Provenance)
                            ▼
                 DEPENDENCY-AWARE FUSION
            • Semantic Group Deduplication
            • Mitigating Discounts (Auth Pass)
            • Non-Linear Accumulation
                            ▼
               THREAT PROBABILITY (0-1.0)
                  + EVIDENCE CONFIDENCE (0-1.0)
                  + IMPACT SCORE (0-1.0)
                            ▼
                    OPERATIONAL RISK (0-100)
                            ▼
                     POLICY ENGINE
            (Non-Quarantining Pre-Delivery Action)
                            ▼
             ┌──────────────┼───────────────┐
             ▼              ▼               ▼
           ALLOW           FLAG       FLAG_AND_ALERT
         (Risk <40)    (40 <= Risk <70)  (Risk >=70)
             │              │               │
             └──────────────┼───────────────┘
                            ▼
                      SMTP FORWARD
            (Injects X-TraceMail Headers)
                            ▼
                   DOWNSTREAM MAIL SERVER
                     (Internal MTA 1026)

SOC & FORENSIC PLATFORM:
├── Review Queue (Analyst Case Workflow & Feedback)
├── Investigation View (Research-Based BEC Analysis & Evidence Breakdown)
├── Fuzzy Campaign Intelligence (Near-Duplicate Wave Clustering)
├── Observable Infrastructure Mapping
└── Telegram Incident Escalation (HIGH / CRITICAL)
```

---

## 1. Operating Modes

### Mode A: Real-Time In-Line SMTP Security Proxy (Primary)
- **Deployment**: Sits directly in inbound mail routing (port 1025) ahead of internal mail servers (Exchange, Postfix, Zimbra, Google Workspace MX).
- **Workflow**:
  1. Accepts inbound RFC822 SMTP stream.
  2. Computes immutable cryptographic SHA-256 digest and preserves raw email structure.
  3. Executes multi-engine inspection pipeline in parallel.
  4. Fuses standardized evidence into multi-dimensional risk scores.
  5. Injects diagnostic `X-TraceMail-*` headers and subject warning tags (optional).
  6. Forwards 100% of deliverable messages downstream to internal MTA (port 1026) without drops or holds.
  7. For `FLAG_AND_ALERT` cases, creates an active SOC Case and dispatches instant Telegram alert.

### Mode B: Retrospective Ingestion & API Connector
- **Deployment**: Historical inbox analysis, Google Workspace / Gmail monitoring, or batch `.eml` ingestion.
- **Workflow**: Ingests historical communications to continuously train and mature the organizational behavioral baseline (`SenderIdentityHistory`, `DomainRelationship`, `ReplyToHistory`).

---

## 2. Evidence Fusion & Decision Model

Every detection engine emits standard `Evidence` objects:
- `evidence_id`: UUIDv4 tracking identifier
- `engine`: Category identifier (`AUTHENTICATION`, `IDENTITY`, `BEHAVIOR`, `CONTENT_AI`, `URL`, `DOMAIN`, `ATTACHMENT`, `RELAY_INFRASTRUCTURE`, `THREAT_INTELLIGENCE`, `CAMPAIGN`)
- `evidence_type`: Specific finding code (e.g., `UNSEEN_NAME_ADDRESS_PAIR`, `PAYMENT_DIVERSION`, `DKIM_PASS`)
- `semantic_group`: Co-dependent deduplication group (e.g., `urgency_pressure`, `sender_identity_history`)
- `independence_group`: Cross-engine independence tracker
- `direction`: `SUPPORTING` (risk increment), `MITIGATING` (risk discount), or `NEUTRAL`
- `severity`, `confidence`, `reliability`, `freshness`: Normalized $0.0 \dots 1.0$ weights
- `research_provenance`: Research attribution tag (e.g., `CIDON_2019_TABLE3`, `TRACEMAIL_TRANSFORMER_EXTENSION`)

---

## 3. Policy Execution Without Quarantine

TraceMail eliminates destructive quarantine workflows in favor of safe, non-quarantining pre-delivery proxying:

| Policy Action | Threshold | Downstream SMTP Behavior | SOC & Escalation |
| :--- | :--- | :--- | :--- |
| **`ALLOW`** | Risk < 40 | Forwarded immediately with basic `X-TraceMail-Analyzed: true` header | Logged in Stream; marked `RESOLVED` / Benign |
| **`FLAG`** | 40 $\le$ Risk < 70 | Forwarded with `X-TraceMail-Flagged: true` and diagnostic severity headers | Logged in Inbox with Warning badge |
| **`FLAG_AND_ALERT`** | Risk $\ge$ 70 | Forwarded with full diagnostic headers + optional `[TraceMail Warning]` subject tag | Escalated to **SOC Review Queue**; instant Telegram notification |
