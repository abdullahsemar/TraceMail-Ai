# TraceMail AI

**AI-powered email threat detection, SMTP security gateway, Gmail monitoring, and forensic intelligence platform.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)
[![React 18](https://img.shields.io/badge/React-18.0+-61DAFB.svg)](https://react.dev/)
[![Research-Grounded](https://img.shields.io/badge/Research-USENIX%20Security%202019-red.svg)](docs/RESEARCH_FOUNDATION.md)

---

## Overview

**TraceMail AI** is an explainable email security proxy and forensic investigation platform that combines research-grounded Business Email Compromise (BEC) detection with transformer NLP analysis, authentication verification, URL/domain intelligence, observable infrastructure tracing, fuzzy campaign clustering, and adaptive evidence fusion.

TraceMail operates primarily as a **non-quarantining pre-delivery inspection, flagging, and alerting platform**. Deliverable SMTP messages are forwarded downstream to internal mailboxes with diagnostic `X-TraceMail-*` security metadata and optional subject warnings, avoiding destructive message drops while escalating high-risk incidents to the SOC Review Queue and instant Telegram alerts.

---

## Features

- **In-Line Pre-Delivery SMTP Gateway**: Intercepts inbound RFC 5321 traffic on port 1025, captures immutable raw RFC822 streams with SHA-256 hashing, and forwards verified messages to downstream MTAs (port 1026).
- **Post-Delivery Gmail Monitoring**: Near-real-time mailbox monitoring via Google OAuth 2.0 and Gmail API (`messages.get`, `users.history`, and Pub/Sub webhook integration).
- **Research-Grounded BEC Detection**: Grounded in Cidon et al. (USENIX Security 2019), implementing sequential Stage A (Metadata/Impersonation) $\rightarrow$ Stage B (Content/Link) analysis, historical sender-name/email pairing statistics, baseline maturity tracking, and enterprise Reply-To provider registries.
- **Transformer NLP Threat Classification**: CPU-efficient DistilBERT model (`spotproject/spot-distilbert-phishing`) for deep contextual intent classification with graceful heuristic fallback when offline.
- **Explainable Evidence Fusion**: Fuses 10 orthogonal detection categories with dependency-aware semantic deduplication and mitigating discounts (`AUTH PASS != SAFE`).
- **Fuzzy Campaign Correlation**: 64-bit cross-platform SimHash near-duplicate clustering correlates distributed phishing waves while preserving exact cryptographic SHA-256 evidence.
- **Observable Infrastructure Mapping**: Multi-hop Received header parsing to trace the earliest reliable public relay hop with ASN and GeoIP enrichment (never misattributed as attacker physical location).
- **Real-Time SOC Web Dashboard**: React 18 interface with Live Stream, Security Inbox, Threat Investigation View, Campaign Intelligence, Review Queue, Audit Trail, and Word DOCX Forensic Reporting.
- **Instant Telegram Escalation**: Real-time alerts dispatched to designated SOC channels for HIGH and CRITICAL severity threats with automated deduplication.

---

## Architecture

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
                             ▼
                THREAT PROBABILITY (0-1.0)
                   + EVIDENCE CONFIDENCE (0-1.0)
                   + IMPACT SCORE (0-1.0)
                             ▼
                     OPERATIONAL RISK (0-100)
                             ▼
                      POLICY ENGINE
             (Non-Quarantining Pre-Delivery Action)
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
```

---

## Requirements

- **Python**: 3.10+ (tested on Python 3.10, 3.11, 3.12, 3.14)
- **Node.js**: 18.0+ and `npm`
- **Operating System**: Linux, macOS, or Windows
- **Memory**: Minimum 2 GB RAM (4 GB recommended if enabling local DistilBERT transformer inference)

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/abdullahsemar/TraceMail-Ai.git
cd TraceMail-Ai
```

### 2. Backend Setup

```bash
cd backend
python -m venv venv

# Activate virtual environment:
# On Linux/macOS:
source venv/bin/activate
# On Windows (cmd):
venv\Scripts\activate.bat
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1

# Install dependencies:
python -m pip install -r requirements.txt

# Create environment configuration from template:
copy .env.example .env    # Windows
# or: cp .env.example .env # Linux/macOS
```

Edit `backend/.env` with your preferred settings.

### 3. Frontend Setup

```bash
cd ../frontend
npm install
```

---

## Running Locally

### Start Backend

From the `backend/` directory with your virtual environment active:

```bash
python run.py
```

Or using Uvicorn directly:

```bash
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The backend initializes services:
- **REST API & Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **System Health Endpoint**: [http://localhost:8000/api/health](http://localhost:8000/api/health)
- **Inbound SMTP Security Gateway**: `127.0.0.1:1025`
- **Mock Downstream Mailbox Receiver**: `127.0.0.1:1026`

### Start Frontend

From the `frontend/` directory:

```bash
npm run dev
```

Open your browser to:
- **SOC Analyst Dashboard**: [http://localhost:5173](http://localhost:5173)

---

## Google Gmail API Setup

To enable post-delivery Gmail monitoring:

1. Go to the [Google Cloud Console](https://console.cloud.google.com/) and create a project.
2. In **APIs & Services** &rarr; **Library**, enable the **Gmail API**.
3. In **APIs & Services** &rarr; **OAuth consent screen**:
   - Choose **External** user type.
   - Fill in application name (`TraceMail AI`) and your developer email.
   - Under **Scopes**, add: `https://www.googleapis.com/auth/gmail.readonly`.
   - Under **Test users**, add your personal/testing Gmail address.
4. In **APIs & Services** &rarr; **Credentials**:
   - Click **Create Credentials** &rarr; **OAuth client ID**.
   - Application type: **Web application**.
   - Authorized JavaScript origins: `http://localhost:5173`
   - Authorized redirect URIs: `http://localhost:8000/api/connectors/gmail/callback`
   - Click **Create** and copy your **Client ID** and **Client Secret**.
5. Add credentials to `backend/.env`:
   ```env
   GOOGLE_CLIENT_ID=your_client_id.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your_client_secret
   GOOGLE_REDIRECT_URI=http://localhost:8000/api/connectors/gmail/callback
   ```
6. Open the Dashboard &rarr; **Mail Connectors** (`/connections`) and click **Connect Google Gmail**.

*Note: If Google credentials are not configured, TraceMail operates in SMTP Gateway mode and reports Gmail status as `NOT_CONFIGURED` without errors.*

---

## Telegram Setup

To receive real-time alerts for high-severity threats:

1. Open Telegram and search for [@BotFather](https://t.me/BotFather).
2. Send `/newbot` and follow instructions to name your bot and obtain your **Bot Token**.
3. Start a conversation with your bot or add it to a SOC group chat.
4. Obtain your numeric **Chat ID** (using [@userinfobot](https://t.me/userinfobot) or `https://api.telegram.org/bot<TOKEN>/getUpdates`).
5. Configure in `backend/.env`:
   ```env
   TELEGRAM_ENABLED=true
   TELEGRAM_BOT_TOKEN=123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ
   TELEGRAM_CHAT_ID=1234567890
   TELEGRAM_MIN_SEVERITY=HIGH
   ```
6. Verify in **System Settings** using the **TEST TELEGRAM ALERT** button.

*Note: If Telegram is disabled or unconfigured, alerts are safely skipped with zero impact on email processing.*

---

## SMTP Gateway Setup

### Personal Gmail vs. Custom Domain

- **Personal Gmail (`@gmail.com`)**: Cannot have a 3rd-party SMTP gateway inserted before Google's MX infrastructure. Use the **Gmail API connector** for post-delivery monitoring.
- **Custom Domain (`@yourdomain.com`)**: Point DNS MX records to TraceMail's public IP to inspect mail **before** it reaches internal mailboxes:
  ```dns
  mx1.yourdomain.com.    IN  A      203.0.113.10
  yourdomain.com.        IN  MX 10  mx1.yourdomain.com.
  ```

See [docs/SMTP_DEPLOYMENT.md](docs/SMTP_DEPLOYMENT.md) for full production deployment instructions.

---

## Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `TRACEMAIL_DEPLOYMENT_MODE` | `hybrid` | Deployment mode: `smtp_gateway`, `gmail`, or `hybrid` |
| `ENV` | `development` | Environment: `development` or `production` |
| `DEBUG` | `true` | Enable verbose diagnostic logging |
| `DATABASE_URL` | `sqlite:///./tracemail.db` | SQLAlchemy connection string |
| `SECRET_KEY` | `CHANGE_ME...` | Session and token secret key |
| `SMTP_GATEWAY_ENABLED` | `true` | Enable inbound SMTP proxy server |
| `SMTP_GATEWAY_HOST` | `127.0.0.1` | Inbound SMTP listening interface |
| `SMTP_GATEWAY_PORT` | `1025` | Inbound SMTP listening port |
| `DOWNSTREAM_SMTP_HOST` | `127.0.0.1` | Destination mail server host |
| `DOWNSTREAM_SMTP_PORT` | `1026` | Destination mail server port |
| `STORE_RAW_EMAIL` | `true` | Enable immutable RFC822 evidence preservation |
| `MAXMIND_DB_PATH` | `""` | Optional path to local GeoLite2-City database |
| `ENABLE_DISTILBERT_DOWNLOAD` | `false` | Download Hugging Face transformer model on first run |
| `GOOGLE_CLIENT_ID` | `""` | Google Cloud OAuth Client ID |
| `GOOGLE_CLIENT_SECRET` | `""` | Google Cloud OAuth Client Secret |
| `TELEGRAM_ENABLED` | `false` | Enable real-time Telegram incident alerts |

---

## Testing

TraceMail includes a comprehensive test suite with 100% synthetic fixtures adhering to RFC 2606 test domains (`example.com`, `example.org`):

```bash
cd backend
python -m pytest tests/ -v
```

Tests cover:
- RFC822 MIME parsing & boundary preservation
- Cryptographic SPF/DKIM/DMARC analysis and mitigating factor logic
- DistilBERT phishing inference with heuristic fallbacks
- SSRF prevention & observable infrastructure mapping
- Multi-hop IPv4 and IPv6 relay path tracing
- Lookalike domain detection & RDAP evaluation
- Tamper-evident SHA-256 hash-chain audit logging
- Full inbound pipeline end-to-end evaluation
- Telegram alerting, deduplication, and connection diagnostics
- Behavioral cold-start handling and Cidon sequential BEC synthesis

---

## Security / Privacy

- **No Secrets Stored in Code**: All authentication secrets, OAuth tokens, and bot credentials are read exclusively from environment variables or local gitignored configurations.
- **Synthetic Test Data**: All automated tests use RFC 2606 reserved domains and RFC 5737 documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- **Privacy Controls**: Raw email storage can be toggled (`STORE_RAW_EMAIL=false`) or governed by retention limits (`RAW_EMAIL_RETENTION_DAYS=90`).
- **No Attacker Geolocation Attribution**: TraceMail strictly reports *Probable Observable Infrastructure* and explicitly documents that relay IP registrations do not represent threat actor physical locations.

See [SECURITY.md](SECURITY.md) for full security disclosures and vulnerability reporting.

---

## Limitations

- **Non-Quarantining Policy**: TraceMail inspects, enriches headers, and alerts, but does not drop or quarantine messages in transit.
- **Cold-Start Behavioral Baseline**: New senders start in `COLD_START` maturity mode with calibrated baseline confidence until sufficient historical interaction is established.
- **Offline ML Execution**: If DistilBERT is not downloaded or the environment is offline, TraceMail operates in heuristic content evaluation mode without interrupting mail flow.

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for complete technical limitations.

---

## Project Structure

```text
TraceMail/
├── backend/
│   ├── app/
│   │   ├── api/               # FastAPI REST routers (inbox, connectors, health, reports)
│   │   ├── background/        # Background schedulers, campaign correlation, retrospective
│   │   ├── connectors/        # Gmail API, IMAP, Outlook connectors
│   │   ├── core/              # Audit hash-chain, evidence schema, policy, security
│   │   ├── database/          # SQLAlchemy models and session initialization
│   │   ├── engines/           # Multi-engine forensic analyzers (BEC, ML, URL, origin, fusion)
│   │   ├── gateway/           # Inbound SMTP proxy, downstream relay, message handler
│   │   ├── notifications/     # Telegram incident alerting and manager
│   │   ├── parsers/           # RFC822 parser, header forensics, relay tracer
│   │   ├── quarantine/        # Review queue & incident state management
│   │   ├── reporting/         # Word DOCX executive report generator
│   │   ├── config.py          # Pydantic Settings and OAuth loader
│   │   └── main.py            # FastAPI entry point & lifespan manager
│   ├── config/
│   │   └── google_oauth.example.json  # OAuth configuration template
│   ├── evidence_storage/      # Immutable raw email storage (.gitkeep)
│   ├── reports/               # Generated executive reports (.gitkeep)
│   ├── research_baselines/    # Comparative TF-IDF/KNN reference implementation
│   ├── tests/                 # Standardized test suite & synthetic fixtures
│   ├── .env.example           # Complete backend environment template
│   ├── requirements.txt       # Python dependencies
│   └── run.py                 # Backend launcher
├── frontend/
│   ├── src/
│   │   ├── components/        # Reusable UI components (ScoreGauge, Sidebar)
│   │   ├── pages/             # Dashboard, Inbox, LiveMonitor, ReviewQueue, Settings, etc.
│   │   ├── services/          # Axios/Fetch API client
│   │   ├── App.jsx            # React root component & routing
│   │   ├── index.css          # Styling & design system tokens
│   │   └── main.jsx           # React DOM bootstrap
│   ├── index.html             # HTML entry point
│   ├── package.json           # Frontend dependencies
│   ├── package-lock.json      # NPM lockfile
│   └── vite.config.js         # Vite configuration
├── docs/
│   ├── ARCHITECTURE.md        # Architectural specification & scoring logic
│   ├── LIMITATIONS.md         # Operational boundaries & forensic constraints
│   ├── RESEARCH_FOUNDATION.md # Cidon et al. USENIX '19 comparative grounding
│   └── SMTP_DEPLOYMENT.md     # Production DNS and SMTP deployment guide
├── .gitignore                 # Comprehensive version control exclusions
├── ARCHITECTURE.md            # Ingestion architecture & overview
├── DEMO.md                    # Verification & demonstration guide
├── DEPLOYMENT.md              # Deployment walkthrough
├── GOOGLE_GMAIL_SETUP.md      # Detailed Google Cloud console walkthrough
├── README.md                  # Project overview & documentation
└── SECURITY.md                # Security policy & reporting guidelines
```
>>>>>>> 9a5d45c (feat: initial commit - sanitized TraceMail AI v2.0 platform)
