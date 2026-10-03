# Research Foundation: High-Precision BEC Detection in TraceMail AI

## 1. Research Paper Citation

> **Cidon, Asaf, Lior Gavish, Itay Bleier, Nadia Korshun, Marco Schweighauser, and Alexey Tsitkin.**  
> *"High Precision Detection of Business Email Compromise."*  
> In **Proceedings of the 28th USENIX Security Symposium (USENIX Security 19)**, pages 1291–1307, Santa Clara, CA, USA, August 2019. USENIX Association.  
> [https://www.usenix.org/conference/usenixsecurity19/presentation/cidon](https://www.usenix.org/conference/usenixsecurity19/presentation/cidon)

---

## 2. Executive Research Attribution & Disclaimers

> [!IMPORTANT]
> **Attribution Notice**: TraceMail AI adapts core architectural insights and statistical identity concepts introduced in the *BEC-Guard* paper by Cidon et al. (USENIX Security 2019).  
> **Performance Disclaimer**: The published performance metrics reported in the paper (e.g., **98.2% precision**, **96.9% recall**, and a **false positive rate of 1 in 5.3 million emails**) were measured on Barracuda Networks' proprietary commercial dataset of 2.5 billion emails across 2 million mailboxes. **These metrics belong strictly to the BEC-Guard evaluation and are not claimed as TraceMail AI's performance.** TraceMail evaluates and reports performance solely on its own internal benchmarks and test suites.

---

## 3. Core Insights from Cidon et al. (2019)

1. **The Nature of Business Email Compromise (BEC)**:
   - Traditional email security systems inspect *malicious* payloads (malware binaries, known malicious IPs/domains) or *volumetric* patterns (spam blasts, mass phishing links).
   - In contrast, ~60% of BEC attacks contain **no link or attachment** (Table 1 of paper: 46.9% wire transfers, 12.2% rapport building, 0.8% PII theft). They consist of clean plain text tailored to specific employees.
   - Attackers frequently impersonate executives (42.9% CEO impersonation, Table 2) or colleagues using personal email accounts or lookalike domains.

2. **Sequential Detection Paradigm (Stage A $\rightarrow$ Stage B)**:
   - Because BEC is extremely rare (less than 1 in 50,000 emails), running generic anomaly models generates unmanageable false positives.
   - Cidon et al. split detection into two sequential stages:
     - **Stage A (Metadata / Impersonation Classifier)**: Evaluates header anomalies, corporate domain membership, display-name collisions, and historical sender address frequency.
     - **Stage B (Content & Link Classifiers)**: Evaluates natural language cues (urgency, financial requests, availability inquiries) and link characteristics only when Stage A indicates impersonation risk.

3. **Historical Organizational Baseline**:
   - Sender identity cannot be judged in isolation; it requires historical communication frequency ($82\%$ of enterprise users communicate using exactly one email address).
   - Known legitimate web services (e.g., LinkedIn, Salesforce, HR portals) that legitimately send emails with mismatched `Reply-To` headers must be handled as mitigating factors rather than false alarms.

---

## 4. TraceMail Implementation vs. Cidon et al.

| Dimension | Cidon et al. (BEC-Guard, 2019) | TraceMail AI Implementation |
| :--- | :--- | :--- |
| **Architecture** | API-based (Office 365 / Gmail inbox polling & folder moving) | **SMTP Pre-Delivery Proxy** + Secondary API / Retrospective Ingestion |
| **Enforcement Policy** | Real-time **Quarantine** (moving message to user quarantine folder) | **Non-Quarantining Inspection**: `ALLOW`, `FLAG`, `FLAG_AND_ALERT` with safe `X-TraceMail` header injection |
| **Stage A: Identity Features** | Random Forest over 6 historical tabular features (Table 3) | [`BehavioralIntelligenceEngine`](../backend/app/engines/behavioral_intelligence.py) implementing Cidon Table 3 + baseline maturity levels (`COLD_START`, `DEVELOPING`, `MATURE`) |
| **Name Normalization** | `<First, Last>` tuples, suffixes, nicknames dictionary | Full Unicode NFKC normalization, nickname dictionary (Bill $\rightarrow$ William), role detection, display-name spoofing |
| **Stage B: Content NLP** | TF-IDF (10,000 unigram/bigram dictionary) + KNN Classifier | **Pretrained Transformer (DistilBERT)** fine-tuned for semantic phishing/BEC cues + structured cue extraction |
| **Stage B: Link Classifier** | Random Forest over Alexa popularity rank, URL length, WHOIS age | Modern [`DomainPopularityProvider`](../backend/app/engines/domain_intel.py) (RDAP registration age, URL entropy, redirect expansion, SSRF-safe resolution) |
| **Decision Logic** | Binary cascade (Impersonation RF $\rightarrow$ Content KNN/RF) | **Multi-Dimensional Evidence Fusion** (Threat Probability, Evidence Confidence, Impact Score, Operational Risk 0-100) |
| **Campaign Tracking** | Not addressed in paper | **Fuzzy Campaign Correlation** (64-bit cross-platform SimHash + Exact SHA-256) |
| **Infrastructure Forensics** | Hop count / basic IP from API | **Multi-hop Received header parsing**, earliest reliable public hop, ASN/GeoIP observable infrastructure |
| **Alerting & SOC Workflow** | User mailbox quarantine folder | **Telegram instant alerts** for HIGH/CRITICAL + dedicated SOC **Review Queue** & Case Management |

---

## 5. Research Traceability Matrix

| Research Concept | Paper Source | TraceMail Component | Status & Modifications |
| :--- | :--- | :--- | :--- |
| **Corporate Domain Verification** | Cidon et al. Table 3 | [`BehavioralIntelligenceEngine.check_corporate_domain`](../backend/app/engines/behavioral_intelligence.py) | **Implemented**. Verified against configured organizational domains. |
| **Reply-To Mismatch Detection** | Cidon et al. Table 3, §3 | [`BehavioralIntelligenceEngine.check_reply_to_mismatch`](../backend/app/engines/behavioral_intelligence.py) | **Implemented**. Emits `REPLY_TO_MISMATCH` with research provenance `CIDON_2019_TABLE3`. |
| **Sender-Name & Address History** | Cidon et al. Table 3, Fig. 1 | [`SenderIdentityHistory`](../backend/app/database/models.py) | **Implemented**. Tracks pairing frequencies; emits `UNSEEN_NAME_ADDRESS_PAIR` or `KNOWN_NAME_ADDRESS_PAIR`. |
| **Known Reply-To Service Registry** | Cidon et al. Table 3, §4.4 | `KNOWN_LEGITIMATE_SERVICES` registry | **Implemented**. Evaluated as `MITIGATING` evidence rather than hardcoded allowlists. |
| **Name & Nickname Normalization** | Cidon et al. §4.4, [36] | [`normalize_display_name`](../backend/app/engines/behavioral_intelligence.py) | **Implemented**. Strips titles/suffixes, maps common diminutive aliases, normalizes Unicode. |
| **Link Domain Age & Registration** | Cidon et al. Table 5 | [`DomainIntelligenceEngine`](../backend/app/engines/domain_intel.py) | **Implemented**. Uses modern RDAP lookup; flags newly registered domains (<30 days). |
| **Link Popularity Provider** | Cidon et al. Table 5 | [`DomainPopularityProvider`](../backend/app/engines/domain_intel.py) | **Modernized**. Replaced obsolete Alexa ranking with configurable enterprise popularity sets and observed domain baselines. |
| **TF-IDF + KNN Baseline** | Cidon et al. §4.4, §7.2 | [`research_baselines/tfidf_knn_baseline.py`](../backend/research_baselines/tfidf_knn_baseline.py) | **Implemented for Comparative Research**. Kept as standalone non-production baseline. |
| **Sequential BEC Synthesis** | Cidon et al. §4.3 | [`BECDetectionEngine`](../backend/app/engines/bec_detector.py) | **Implemented**. Stage A Impersonation prob + Stage B Content/Link synthesis. Generic phishing runs in parallel. |

---

## 6. TraceMail Extensions (Not in Cidon et al.)

1. **Transformer-Based NLP (`threat_ml.py`)**:
   Uses DistilBERT to capture contextual nuances and complex social engineering phrasing beyond unigram/bigram TF-IDF word counts.
2. **Adaptive Dependency-Aware Evidence Fusion (`fusion.py`)**:
   Accumulates heterogeneous signals across 10 engine categories while penalizing co-dependent signals (e.g. redundant urgency keywords) and applying dampening discounts for mitigating authentication/relationship proof.
3. **Non-Quarantining SMTP Pre-Delivery Proxy (`downstream.py`, `handler.py`)**:
   Operates in-line with standard mail transfer agents (Postfix, Exchange, Sendmail) to inject safe, explainable `X-TraceMail-*` diagnostic headers while preserving downstream delivery.
4. **Fuzzy Campaign Correlation (`campaign_correlation.py`)**:
   Calculates 64-bit SimHash structural fingerprints across message bodies and subjects to cluster near-duplicate spear-phishing waves without sacrificing cryptographic SHA-256 evidence integrity.
5. **Responsible Infrastructure & Origin Analysis (`relay_tracer.py`, `origin_forensics.py`)**:
   Reconstructs multi-hop routing paths, identifying observable boundary infrastructure, ASN, and GeoIP without making unsubstantiated claims about attacker physical locations.
6. **Dual-Mode Operation**:
   Simultaneously supports live SMTP proxy inspection and retrospective historical baseline ingestion (via Gmail API / EML batch imports) using the same normalized schemas.
