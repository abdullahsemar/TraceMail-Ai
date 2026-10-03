# TraceMail AI — Security, Forensic & Research Limitations

This document outlines key operational boundaries, forensic principles, and algorithmic limitations of TraceMail AI.

---

## 1. Non-Quarantining Pre-Delivery Policy
- **No In-Flight Drops or Deletions**: TraceMail AI operates as an in-line SMTP inspection and flagging proxy. It does not drop, hold, or quarantine emails in transit.
- **Header Enrichment & Tagging**: High-risk and critical emails are delivered downstream with diagnostic headers (`X-TraceMail-Risk-Score`, `X-TraceMail-Severity`, `X-TraceMail-Classification`, `X-TraceMail-Flagged`) and escalated to the SOC Review Queue and Telegram.
- **Delivery Availability**: All messages remain deliverable unless downstream SMTP transport fails.

---

## 2. Historical Behavioral Baselines & Cold-Start Limits
- **Data Requirement**: The behavioral baseline engine (inspired by Cidon et al. 2019) requires historical corporate email patterns to establish sender-name/email pairing frequency and recipient graphs.
- **Cold-Start Handling**: For newly onboarded organizations or new employees, behavioral status is marked `COLD_START` with intentionally lowered confidence ($<0.30$). TraceMail does not fabricate baseline statistics and relies on orthogonal detection layers (Auth, Content, URLs, Domain).
- **Maturity Progression**: Behavioral evidence confidence scales through `DEVELOPING` ($\ge 50$ samples) to `MATURE` ($\ge 200$ samples and $\ge 14$ days).

---

## 3. Observable Infrastructure vs. Attacker Physical Location
- **IP Geolocation $\neq$ Attacker Physical Location**: Geolocation lookups reflect the registration location of the earliest observable public relay hop (MTA/VPS/VPN/proxy), **NOT** the physical location of the threat actor.
- **Terminology**: TraceMail strictly uses *"Probable Observable Infrastructure"* and *"Observed Infrastructure Location"*. It never refers to *"Hacker Location"* or *"Attacker GPS"*.
- **Relay Evasion**: Attackers can route through open relays, compromised legitimate mail servers, Tor exit nodes, commercial VPNs, and bulletproof hosting providers to obfuscate true origin.

---

## 4. Email Authentication (SPF / DKIM / DMARC)
- **Authentication PASS $\neq$ Safe**: An attacker operating through a legitimate compromised Microsoft 365 or Google Workspace account will typically pass SPF, DKIM, and DMARC checks.
- **Mitigating Factor Only**: Authentication PASS is treated as mitigating evidence in the fusion engine; it never automatically grants an unconditional `ALLOW` if strong BEC or phishing cues exist.
- **Header Forgery**: Received headers added by untrusted intermediate relays can be forged. TraceMail parses the chain in reverse starting from the trustworthy receiving boundary.

---

## 5. Machine Learning & Transformer Predictions
- **Probabilistic Scoring**: The DistilBERT transformer outputs continuous probability scores for credential theft, financial fraud, and social engineering. Transformer predictions are probabilistic evidence inputs and do not solely dictate the verdict.
- **Adversarial Perturbation**: Sophisticated adversaries using zero-width spaces, adversarial phrasing, or image-embedded text may evade NLP models. TraceMail combines NLP with behavioral anomaly detection, URL inspection, and header forensics.

---

## 6. Threat Intelligence & Enrichment
- **Unknown Status**: When external threat intelligence feeds or local MaxMind GeoIP databases are unconfigured, TraceMail explicitly marks indicators as `UNKNOWN`. It never fabricates scores or assumes `UNKNOWN` means `CLEAN`.
- **Zero-Day Indicators**: Brand new attack domains or bulletproof VPS IPs will not immediately appear on threat blocklists.

---

## 7. Fuzzy Campaign Similarity
- **Similarity $\neq$ Malice**: 64-bit SimHash near-duplicate clustering groups emails sharing similar textual and HTML structures. Similarity proves that two emails belong to the same campaign wave; maliciousness is determined by the fused evidence verdict.
- **Threshold Calibration**: Campaign correlation thresholds (`CAMPAIGN_SIMILARITY_STRONG = 0.85`, `CAMPAIGN_SIMILARITY_REVIEW = 0.70`) represent heuristic baselines and require periodic operational calibration.

---

## 8. Research Benchmark Disclaimers
- **BEC-Guard Numbers**: Published figures from Cidon et al. (USENIX Security 2019) such as 98.2% precision and 1 in 5.3 million false positive rate were measured on Barracuda Networks' proprietary commercial dataset of 2.5 billion emails.
- **Independent Evaluation**: TraceMail AI's performance is measured and validated strictly on its own evaluation datasets, benchmark suites, and unit tests.
