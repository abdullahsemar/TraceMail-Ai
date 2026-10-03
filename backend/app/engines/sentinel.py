from app.config import settings

class FastSentinelEngine:
    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".hta", ".ps1", 
        ".iso", ".img", ".jar", ".wsf", ".cpl", ".rar", ".7z", ".docm", ".xlsm"
    }
    
    URGENCY_KEYWORDS = [
        "urgent", "immediate action", "asap", "within 24 hours", "account suspended",
        "wire transfer", "payment overdue", "past due", "payroll update", "bank transfer",
        "confirm password", "verify identity", "security alert", "critical notice"
    ]
    
    SUSPICIOUS_TLDS = {
        ".top", ".xyz", ".buzz", ".monster", ".work", ".click", ".surf", ".icu", ".cam"
    }

    @classmethod
    def screen(cls, parsed_email: dict, header_analysis: dict) -> dict:
        score = 0.0
        flags = []
        
        if header_analysis.get("display_name_spoofed"):
            score += 35.0
            flags.append("Display name spoofing / title impersonation detected")
            
        if header_analysis.get("reply_to_mismatch"):
            score += 25.0
            flags.append("Reply-To domain mismatch")
            
        if header_analysis.get("return_path_mismatch"):
            score += 15.0
            flags.append("Return-Path mismatch")
            
        subject = parsed_email.get("subject", "").lower()
        body = parsed_email.get("body_text", "").lower()
        combined_text = f"{subject} {body}"
        
        urgency_hits = [kw for kw in cls.URGENCY_KEYWORDS if kw in combined_text]
        if urgency_hits:
            score += min(30.0, len(urgency_hits) * 10.0)
            flags.append(f"High-urgency / financial keywords: {', '.join(urgency_hits[:3])}")
            
        attachments = parsed_email.get("attachments", [])
        for att in attachments:
            fname = att.get("filename", "").lower()
            for ext in cls.SUSPICIOUS_EXTENSIONS:
                if fname.endswith(ext):
                    score += 40.0
                    flags.append(f"Suspicious attachment executable/script extension: {fname}")
                    break

        urls = parsed_email.get("urls", [])
        if urls:
            for u in urls:
                url_str = u.get("url", "").lower()
                for tld in cls.SUSPICIOUS_TLDS:
                    if tld in url_str:
                        score += 20.0
                        flags.append(f"Suspicious high-risk TLD in URL: {tld}")
                        break
                        
                vis = u.get("visible_text", "").lower()
                if "@" in vis or "http" in vis:
                    if vis not in url_str:
                        score += 35.0
                        flags.append(f"Deceptive link: visible anchor '{vis}' differs from target '{url_str}'")

        final_score = min(100.0, score)
        if final_score < settings.SENTINEL_FAST_ALLOW_THRESHOLD:
            decision = "ALLOW_FAST"
            severity = "SAFE"
        elif final_score < settings.SENTINEL_DEEP_SCAN_THRESHOLD:
            decision = "DEEP_SCAN"
            severity = "SUSPICIOUS"
        else:
            decision = "QUARANTINE_PENDING_ANALYSIS"
            severity = "HIGH" if final_score < 75 else "CRITICAL"
            
        return {
            "sentinel_score": round(final_score, 1),
            "severity": severity,
            "decision": decision,
            "screening_flags": flags
        }
