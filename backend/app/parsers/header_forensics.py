import re
from typing import Dict, Any, List
from app.core.evidence import Evidence

class HeaderForensics:
    """
    Header Forensics & Authentication Analysis Parser.
    
    Principles:
    - AUTHENTICATION PASS != SAFE (compromised legitimate accounts can pass SPF/DKIM).
    - SPF/DKIM/DMARC PASS emitted as MITIGATING evidence.
    - Emits Standard Evidence V2 with research provenance citations.
    """
    @staticmethod
    def analyze_headers(parsed_email: Dict[str, Any]) -> Dict[str, Any]:
        headers = parsed_email.get("headers", {})
        sender_email = parsed_email.get("sender_email", "")
        sender_display_name = parsed_email.get("sender_display_name", "")
        reply_to = parsed_email.get("reply_to")
        return_path = parsed_email.get("return_path")
        
        sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
        reply_to_domain = reply_to.split("@")[-1].lower() if reply_to and "@" in reply_to else None
        return_path_domain = return_path.split("@")[-1].lower() if return_path and "@" in return_path else None
        
        evidence_list: List[Evidence] = []
        anomalies: List[str] = []
        
        # 1. Reply-To Analysis (Cidon et al. 2019 Table 3)
        reply_to_mismatch = False
        if reply_to and reply_to.lower() != sender_email.lower():
            reply_to_mismatch = True
            if reply_to_domain and reply_to_domain != sender_domain:
                anomalies.append(f"Reply-To domain mismatch: sent from '{sender_domain}', response redirected to '{reply_to_domain}'")
                evidence_list.append(Evidence(
                    engine="IDENTITY",
                    type="REPLY_TO_DOMAIN_MISMATCH",
                    semantic_group="reply_to_mismatch",
                    independence_group="reply_to_identity",
                    value=reply_to,
                    severity=0.75,
                    confidence=0.95,
                    reliability=0.92,
                    freshness=1.0,
                    direction="SUPPORTING",
                    description=f"Reply-To domain '{reply_to_domain}' diverges from sender domain '{sender_domain}'",
                    source="EMAIL_HEADER",
                    research_provenance="CIDON_2019_TABLE3"
                ))
            else:
                anomalies.append(f"Reply-To mailbox mismatch on same domain: from '{sender_email}' to '{reply_to}'")
                evidence_list.append(Evidence(
                    engine="IDENTITY",
                    type="REPLY_TO_MAILBOX_MISMATCH",
                    semantic_group="reply_to_mismatch",
                    independence_group="reply_to_identity",
                    value=reply_to,
                    severity=0.35,
                    confidence=0.90,
                    reliability=0.85,
                    freshness=1.0,
                    direction="SUPPORTING",
                    description=f"Reply-To specifies alternate mailbox '{reply_to}' on same domain",
                    source="EMAIL_HEADER",
                    research_provenance="CIDON_2019_TABLE3"
                ))
        elif reply_to and reply_to.lower() == sender_email.lower():
            evidence_list.append(Evidence(
                engine="IDENTITY",
                type="REPLY_TO_ALIGNED",
                semantic_group="reply_to_mismatch",
                independence_group="reply_to_identity",
                value=reply_to,
                severity=0.0,
                confidence=0.95,
                reliability=0.90,
                freshness=1.0,
                direction="MITIGATING",
                description="Reply-To address is aligned with From header",
                source="EMAIL_HEADER",
                research_provenance="CIDON_2019_TABLE3"
            ))

        # 2. Return-Path Analysis
        return_path_mismatch = False
        if return_path and return_path.lower() != sender_email.lower():
            return_path_mismatch = True
            if return_path_domain and return_path_domain != sender_domain:
                anomalies.append(f"Return-Path domain mismatch: '{return_path_domain}' vs sender '{sender_domain}'")
                evidence_list.append(Evidence(
                    engine="IDENTITY",
                    type="RETURN_PATH_MISMATCH",
                    semantic_group="identity_anomaly",
                    independence_group="return_path_identity",
                    value=return_path,
                    severity=0.40,
                    confidence=0.90,
                    reliability=0.85,
                    freshness=1.0,
                    direction="SUPPORTING",
                    description=f"Envelope Return-Path domain '{return_path_domain}' differs from header From '{sender_domain}'",
                    source="EMAIL_HEADER",
                    research_provenance="STANDARD_EMAIL_AUTH"
                ))

        # 3. Display-Name Spoofing Analysis (Cidon et al. 2019 §4.4)
        display_name_spoofed = False
        if sender_display_name:
            email_in_display = re.findall(r'[\w\.-]+@[\w\.-]+', sender_display_name)
            if email_in_display:
                contained_email = email_in_display[0].lower()
                if contained_email != sender_email.lower():
                    display_name_spoofed = True
                    anomalies.append(f"Display-name spoofing detected: '{sender_display_name}' embeds '{contained_email}' but sender is '{sender_email}'")
                    evidence_list.append(Evidence(
                        engine="IDENTITY",
                        type="DISPLAY_NAME_EMAIL_INJECTION",
                        semantic_group="domain_impersonation",
                        independence_group="display_name_spoofing",
                        value=sender_display_name,
                        severity=0.85,
                        confidence=0.98,
                        reliability=0.95,
                        freshness=1.0,
                        direction="SUPPORTING",
                        description=f"Display name embeds deceptive target address '{contained_email}' differing from actual sender '{sender_email}'",
                        source="EMAIL_HEADER",
                        research_provenance="CIDON_2019_TABLE3"
                    ))
                    
            exec_keywords = ["ceo", "cfo", "chief executive", "president", "director", "payroll", "finance officer", "wire transfer", "hr department"]
            if any(k in sender_display_name.lower() for k in exec_keywords) and any(d in sender_domain for d in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]):
                anomalies.append(f"Executive or corporate title used with free webmail domain: '{sender_display_name}' from '{sender_domain}'")
                evidence_list.append(Evidence(
                    engine="IDENTITY",
                    type="EXECUTIVE_TITLE_FREE_WEBMAIL",
                    semantic_group="executive_impersonation",
                    independence_group="display_name_spoofing",
                    value=sender_display_name,
                    severity=0.78,
                    confidence=0.92,
                    reliability=0.90,
                    freshness=1.0,
                    direction="SUPPORTING",
                    description=f"Executive corporate title '{sender_display_name}' utilized with generic freemail domain '{sender_domain}'",
                    source="EMAIL_HEADER",
                    research_provenance="CIDON_2019_TABLE3"
                ))

        # 4. SPF / DKIM / DMARC Authentication Parsing (Research: AUTH PASS != SAFE)
        auth_results_raw = headers.get("Authentication-Results", "")
        if isinstance(auth_results_raw, list):
            auth_results_raw = " ".join(auth_results_raw)
            
        received_spf_raw = headers.get("Received-SPF", "")
        if isinstance(received_spf_raw, list):
            received_spf_raw = " ".join(received_spf_raw)
            
        dkim_sig_present = "DKIM-Signature" in headers
        arc_seal_present = "ARC-Seal" in headers
        
        # SPF
        spf_result = "UNKNOWN"
        spf_domain = None
        if "spf=pass" in auth_results_raw.lower() or "pass" in received_spf_raw.lower():
            spf_result = "PASS"
            spf_match = re.search(r'header\.from=([\w\.-]+)', auth_results_raw, re.IGNORECASE)
            spf_domain = spf_match.group(1) if spf_match else sender_domain
            evidence_list.append(Evidence(
                engine="AUTHENTICATION",
                type="SPF_PASS",
                semantic_group="auth_spf",
                independence_group="email_authentication",
                value=spf_domain,
                severity=0.0,
                confidence=0.95,
                reliability=0.90,
                freshness=1.0,
                direction="MITIGATING",
                description=f"SPF record valid and verified for '{spf_domain}'",
                source="EMAIL_HEADER",
                research_provenance="STANDARD_EMAIL_AUTH"
            ))
        elif "spf=fail" in auth_results_raw.lower() or "fail" in received_spf_raw.lower():
            spf_result = "FAIL"
            anomalies.append("SPF verification failed")
            evidence_list.append(Evidence(
                engine="AUTHENTICATION",
                type="SPF_FAIL",
                semantic_group="auth_spf",
                independence_group="email_authentication",
                value=sender_domain,
                severity=0.75,
                confidence=0.95,
                reliability=0.92,
                freshness=1.0,
                direction="SUPPORTING",
                description=f"Sender IP address not authorized by SPF policy for '{sender_domain}'",
                source="EMAIL_HEADER",
                research_provenance="STANDARD_EMAIL_AUTH"
            ))
        elif "spf=softfail" in auth_results_raw.lower():
            spf_result = "SOFTFAIL"
            anomalies.append("SPF softfail")
            evidence_list.append(Evidence(
                engine="AUTHENTICATION",
                type="SPF_SOFTFAIL",
                semantic_group="auth_spf",
                independence_group="email_authentication",
                value=sender_domain,
                severity=0.45,
                confidence=0.90,
                reliability=0.88,
                freshness=1.0,
                direction="SUPPORTING",
                description=f"Sender IP generated SPF softfail for '{sender_domain}'",
                source="EMAIL_HEADER",
                research_provenance="STANDARD_EMAIL_AUTH"
            ))

        # DKIM
        dkim_result = "UNKNOWN"
        dkim_domain = None
        if "dkim=pass" in auth_results_raw.lower():
            dkim_result = "PASS"
            dkim_match = re.search(r'header\.d=([\w\.-]+)', auth_results_raw, re.IGNORECASE)
            dkim_domain = dkim_match.group(1) if dkim_match else sender_domain
            evidence_list.append(Evidence(
                engine="AUTHENTICATION",
                type="DKIM_PASS",
                semantic_group="auth_dkim",
                independence_group="email_authentication",
                value=dkim_domain,
                severity=0.0,
                confidence=0.98,
                reliability=0.95,
                freshness=1.0,
                direction="MITIGATING",
                description=f"DKIM cryptographic signature verified for domain '{dkim_domain}'",
                source="EMAIL_HEADER",
                research_provenance="STANDARD_EMAIL_AUTH"
            ))
        elif "dkim=fail" in auth_results_raw.lower():
            dkim_result = "FAIL"
            anomalies.append("DKIM signature validation failed")
            evidence_list.append(Evidence(
                engine="AUTHENTICATION",
                type="DKIM_FAIL",
                semantic_group="auth_dkim",
                independence_group="email_authentication",
                value=sender_domain,
                severity=0.80,
                confidence=0.98,
                reliability=0.95,
                freshness=1.0,
                direction="SUPPORTING",
                description="DKIM cryptographic signature verification failed (body or headers altered)",
                source="EMAIL_HEADER",
                research_provenance="STANDARD_EMAIL_AUTH"
            ))
        elif dkim_sig_present:
            dkim_result = "PRESENT_UNVERIFIED"

        # DMARC
        dmarc_result = "UNKNOWN"
        dmarc_policy = None
        if "dmarc=pass" in auth_results_raw.lower():
            dmarc_result = "PASS"
            evidence_list.append(Evidence(
                engine="AUTHENTICATION",
                type="DMARC_PASS",
                semantic_group="auth_dmarc",
                independence_group="email_authentication",
                value=sender_domain,
                severity=0.0,
                confidence=0.98,
                reliability=0.95,
                freshness=1.0,
                direction="MITIGATING",
                description=f"DMARC alignment verified for '{sender_domain}'",
                source="EMAIL_HEADER",
                research_provenance="STANDARD_EMAIL_AUTH"
            ))
        elif "dmarc=fail" in auth_results_raw.lower():
            dmarc_result = "FAIL"
            pol_match = re.search(r'action=(\w+)', auth_results_raw, re.IGNORECASE)
            dmarc_policy = pol_match.group(1) if pol_match else "none"
            anomalies.append(f"DMARC validation failed (policy={dmarc_policy})")
            evidence_list.append(Evidence(
                engine="AUTHENTICATION",
                type="DMARC_FAIL",
                semantic_group="auth_dmarc",
                independence_group="email_authentication",
                value=f"policy={dmarc_policy}",
                severity=0.85,
                confidence=0.98,
                reliability=0.95,
                freshness=1.0,
                direction="SUPPORTING",
                description=f"DMARC alignment check failed for '{sender_domain}' (configured policy: '{dmarc_policy}')",
                source="EMAIL_HEADER",
                research_provenance="STANDARD_EMAIL_AUTH"
            ))

        auth_summary = f"SPF: {spf_result} | DKIM: {dkim_result} | DMARC: {dmarc_result}"
        
        return {
            "sender_email": sender_email,
            "sender_display_name": sender_display_name,
            "reply_to": reply_to,
            "return_path": return_path,
            "reply_to_mismatch": reply_to_mismatch,
            "return_path_mismatch": return_path_mismatch,
            "display_name_spoofed": display_name_spoofed,
            "spf": {"result": spf_result, "domain": spf_domain},
            "dkim": {"result": dkim_result, "domain": dkim_domain, "sig_present": dkim_sig_present},
            "dmarc": {"result": dmarc_result, "policy": dmarc_policy},
            "has_arc": arc_seal_present,
            "anomalies": anomalies,
            "summary": auth_summary,
            "evidence": evidence_list
        }
