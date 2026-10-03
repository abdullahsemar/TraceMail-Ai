# TraceMail AI - Demonstration & Verification Guide

## 1. Fast Demonstration via SOC Dashboard
1. Open the dashboard at `http://localhost:5173`.
2. In the top bar, click any of the **Demo Simulator** buttons:
   - **Safe Email**: Legitimate operations sync. Passes screening and relays downstream to port 1026.
   - **Auth BEC (SPF Pass)**: Simulates a CEO payment detail change with authenticated SPF. Triggers BEC detection and automated quarantine.
   - **Credential Phish**: Simulates an urgent password expiration notice. Intercepted and quarantined.
   - **Impersonation**: Simulates display-name spoofing with free webmail return.
3. Observe live stats incrementing, real-time alerts appearing in the stream, and forensic case records being opened.

---

## 2. Real SMTP Traffic Injection via Python / Terminal

Send an actual SMTP message to port 1025 using Python:

```python
import smtplib

msg = """From: "Accounting" <billing@example.xyz>
To: target@organization.com
Subject: URGENT: Wire Transfer Account Modified
Date: Sat, 05 Sep 2026 12:00:00 +0000

Please find updated routing number for today's invoice. Process wire transfer immediately.
"""

with smtplib.SMTP('127.0.0.1', 1025) as server:
    server.sendmail('billing@example.xyz', ['target@organization.com'], msg)
    print("Real SMTP email transmitted to TraceMail Security Gateway.")
```

---

## 3. Investigating & Quarantining Messages
1. Navigate to **Quarantine Queue** (`/quarantine`) to inspect held messages.
2. Click **Inspect** to review the dual gauges: **Threat Risk (0-100)** vs **Origin Confidence (0-100)**, SPF/DKIM authentication breakdown, and Probable Observable Infrastructure.
3. Click **Release Downstream** to relay the original preserved RFC822 bytes to the downstream SMTP server, or click **Block** to retain evidence permanently.

---

## 4. Weekly Intelligence Report Generation
1. Navigate to **Weekly Reports** (`/reports`).
2. Click **Generate Weekly Report**.
3. Download and open the generated `.docx` file summarizing incidents, threat breakdowns, and defensive actions.
