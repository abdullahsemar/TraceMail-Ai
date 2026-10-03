import hashlib
import mimetypes
import os
from typing import List, Dict, Any

class AttachmentSecurityAnalyzer:
    """
    Analyzes attachments for:
    - SHA-256 calculation
    - MIME / extension type mismatch (e.g. executable disguised as PDF)
    - High-risk / script extension identification
    """

    DANGEROUS_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".hta", ".ps1",
        ".iso", ".img", ".jar", ".wsf", ".cpl", ".rar", ".7z", ".docm", ".xlsm"
    }

    @classmethod
    def analyze_attachments(cls, attachments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        analyzed = []
        for att in attachments:
            filename = att.get("filename", "")
            content_type = att.get("content_type", "")
            raw_payload = att.get("payload_bytes") or b""
            
            sha256_hash = hashlib.sha256(raw_payload).hexdigest() if raw_payload else att.get("sha256", "UNKNOWN")
            _, ext = os.path.splitext(filename.lower())
            
            is_risky = ext in cls.DANGEROUS_EXTENSIONS
            expected_mime, _ = mimetypes.guess_type(filename)
            
            # MIME mismatch detection
            mime_mismatch = False
            if expected_mime and content_type and expected_mime.lower() != content_type.lower():
                if "octet-stream" not in content_type:
                    mime_mismatch = True
                    is_risky = True

            analyzed.append({
                "filename": filename,
                "content_type": content_type,
                "size_bytes": att.get("size_bytes", len(raw_payload)),
                "sha256": sha256_hash,
                "extension": ext,
                "is_risky": is_risky,
                "mime_mismatch": mime_mismatch,
                "reputation": "UNKNOWN"
            })
        return analyzed
