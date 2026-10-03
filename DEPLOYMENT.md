# TraceMail AI - Deployment Guide

## Prerequisites
- Python 3.10+
- Node.js 18+ & npm
- SQLite (Local Dev) or PostgreSQL (Production)

---

## 1. Local Development Setup

### Backend Setup
```bash
cd backend
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
python run.py
```
Backend will start:
- FastAPI REST API & Swagger on `http://localhost:8000` (docs at `/docs`)
- TraceMail Pre-Delivery SMTP Gateway on `0.0.0.0:1025`
- Mock Downstream Mailbox Receiver on `127.0.0.1:1026`
- Continuous Retrospective Threat Intelligence Background Scheduler

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Access the SOC Analyst Dashboard at `http://localhost:5173`.

---

## 2. Production Enterprise Deployment

### Step A: DNS MX Records Configuration
Point your domain's primary MX record to TraceMail AI's gateway host:
```dns
example.com.   IN   MX   10   mx1.tracemail.security.
```

### Step B: Downstream Relay Delivery
In `backend/.env`, configure your downstream corporate mail exchange (e.g. Microsoft 365 or Google Workspace inbound server):
```env
DOWNSTREAM_SMTP_HOST=your-org-mail.mail.protection.outlook.com
DOWNSTREAM_SMTP_PORT=25
DOWNSTREAM_SMTP_USE_TLS=True
```

### Step C: Post-Arrival Mailbox Connectors
- Configure Google Cloud Pub/Sub and OAuth Client ID for Gmail API monitoring.
- Register an Azure App Registration for Microsoft Graph Webhook notifications.
