# TraceMail AI — Production SMTP Gateway & Domain Routing Deployment Guide

This document outlines the architecture, DNS configuration, and server prerequisites for routing email from a custom domain through the **TraceMail AI Pre-Delivery SMTP Gateway**.

---

## 1. Architectural Overview: Gmail API vs. SMTP Gateway

| Capability | Personal / Workspace Gmail (`GMAIL_API`) | Custom Controlled Domain (`SMTP_GATEWAY`) |
| :--- | :--- | :--- |
| **Ingestion Mechanism** | Google OAuth 2.0 & Gmail API (`messages.get`) | Standards-based Inbound SMTP MTA (RFC 5321) |
| **Inspection Timing** | **Post-Delivery / Near-Realtime** | **Pre-Delivery Inline Interception** |
| **Enforcement Actions**| SOC Alerting, Flagging, Case Creation | **Hold, Quarantine, Forward, Block** |
| **DNS Requirements** | None (Runs over Google Cloud OAuth) | Public DNS MX & A records pointing to Gateway |
| **Evidence Custody** | SHA-256 raw RFC822 immutable preservation | SHA-256 raw RFC822 immutable preservation |

---

## 2. Inbound Pre-Delivery Architecture

```
                                 THE INTERNET
                                      │
                        (Sending MTA: Gmail, M365, etc.)
                                      │
                                      ▼  (Port 25)
                     ┌──────────────────────────────────┐
                     │    Public DNS MX Resolution      │
                     │    mx1.organization.com (A Rec)  │
                     └────────────────┬─────────────────┘
                                      │
                                      ▼
             ┌──────────────────────────────────────────────────┐
             │       TRACEMAIL AI SMTP SECURITY GATEWAY         │
             │           (Port 25 or 1025 via Reverse Proxy)    │
             │                                                  │
             │  1. Inbound SMTP Handshake & Size Validation     │
             │  2. Raw RFC822 Capture & SHA-256 Hash Generation │
             │  3. Multi-Engine Threat & NLP Forensics          │
             │  4. Evidence Fusion & Verdict Engine             │
             │  5. Policy Enforcement:                          │
             │     - LOW/SAFE: Forward to Downstream Mailbox    │
             │     - SUSPICIOUS: Forward + SOC Alert            │
             │     - HIGH/CRITICAL: Hold in Quarantine Queue    │
             └────────────────┬─────────────────┬───────────────┘
                              │                 │
            (Clean Email)     │                 │ (High / Critical Threat)
                              ▼                 ▼
          ┌─────────────────────────┐     ┌────────────────────────┐
          │  Downstream Mail Server │     │  TraceMail Quarantine  │
          │  (Exchange, Postfix,    │     │  & Telegram Alert      │
          │   Mailcow, Zimbra)      │     │  (Analyst Inspection)  │
          └─────────────────────────┘     └────────────────────────┘
```

---

## 3. Production Deployment Prerequisites

To deploy TraceMail SMTP Gateway on a live domain:

### A. Dedicated VPS / Cloud Server
- **Operating System**: Linux (Ubuntu 22.04 LTS / Debian 12 recommended) or Windows Server
- **IP Address**: Dedicated static Public IPv4 address
- **Port 25**: Ensure your cloud provider permits outbound & inbound Port 25 (DigitalOcean, AWS, Linode, and Hetzner require unblocking requests).

### B. DNS Records Configuration
Configure the following records in your DNS zone (Cloudflare, Route53, Namecheap, etc.):

```dns
; 1. A Record for the Mail Gateway
mx1.yourdomain.com.    IN  A      203.0.113.10

; 2. Primary MX Record
yourdomain.com.        IN  MX 10  mx1.yourdomain.com.

; 3. Reverse DNS (PTR Record) - Configured at your VPS Provider
203.0.113.10           IN  PTR    mx1.yourdomain.com.

; 4. SPF Record (Defines authorized outbound senders)
yourdomain.com.        IN  TXT    "v=spf1 mx ~all"
```

---

## 4. Port 25 Binding & Firewall Setup

In Linux production, standard non-root users cannot bind to ports below 1024. Use **iptables**, **nftables**, or **HAProxy** to route traffic to TraceMail's port 1025:

### Option A: Port Forwarding via iptables
```bash
# Forward incoming WAN port 25 traffic to TraceMail on port 1025
sudo iptables -t nat -A PREROUTING -p tcp --dport 25 -j REDIRECT --to-port 1025

# Save rules
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

### Option B: Systemd Service with Capability Binding
```ini
[Unit]
Description=TraceMail AI SMTP Security Gateway
After=network.target

[Service]
Type=simple
User=tracemail
WorkingDirectory=/opt/tracemail/backend
ExecStart=/opt/tracemail/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=always

[Install]
WantedBy=multi-user.target
```

---

## 5. Downstream Relay Configuration (`backend/.env`)

Configure your target corporate mailbox server that receives verified clean emails:

```env
# Inbound Gateway Listening Settings
SMTP_GATEWAY_ENABLED=true
SMTP_GATEWAY_HOST=0.0.0.0
SMTP_GATEWAY_PORT=1025

# Target Downstream Mail Server (Postfix, Exchange, Zimbra, etc.)
DOWNSTREAM_SMTP_HOST=10.0.0.15
DOWNSTREAM_SMTP_PORT=25
DOWNSTREAM_SMTP_USE_TLS=false
DOWNSTREAM_SMTP_STARTTLS=true
DOWNSTREAM_SMTP_USERNAME=
DOWNSTREAM_SMTP_PASSWORD=
```

---

## 6. Verification & Safe Diagnostics

1. **Verify Subsystem Health**:
   Open **System Settings** in the TraceMail Web Dashboard or query `GET /api/health`.
2. **Execute Connection Test**:
   Click **TEST DOWNSTREAM SMTP** in the Settings page or send `POST /api/smtp/test-downstream`. This verifies DNS, TCP, and TLS reachability to your destination mail server without injecting fake email artifacts.
3. **Send Real Test Email**:
   Send a message from an external address (e.g. Gmail or Outlook) to `user@yourdomain.com`. The message will appear in real time on the **Security Inbox** page.
