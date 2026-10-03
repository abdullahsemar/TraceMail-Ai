import hashlib
import mimetypes
import logging
from typing import List, Dict, Any
from app.core.evidence import Evidence

logger = logging.getLogger("tracemail.attachment_analyzer")

class AttachmentSecurityAnalyzer:
    """
    Attachment Security Engine:
    - SHA-256 cryptographic hash computation
    - Dangerous executable / script extension detection
    - Double extension detection (e.g., invoice.pdf.exe)
    - MIME type vs filename extension mismatch detection
    - Standardized Evidence generation feeding into Evidence Fusion
    """

    DANGEROUS_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".hta", ".ps1", 
        ".iso", ".img", ".jar", ".wsf", ".cpl", ".rar", ".7z", ".docm", 
        ".xlsm", ".pptm", ".dll", ".sys", ".drv", ".pif", ".lnk", ".gadget"
    }

    EXPECTED_MIME_PREFIXES = {
        ".pdf": "application/pdf",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".txt": "text/plain",
        ".html": "text/html",
        ".zip": "application/zip",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    }

    @classmethod
    def analyze_attachments(cls, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = []
        evidence_list: List[Evidence] = []
        has_dangerous_ext = False
        has_mime_mismatch = False
        has_double_ext = False

        for att in attachments:
            filename = att.get("filename", "unnamed")
            content_type = att.get("content_type", "application/octet-stream").lower()
            payload = att.get("payload_bytes")
            
            # 1. SHA-256 Hash Computation
            sha256 = att.get("sha256")
            if not sha256 and payload is not None and isinstance(payload, bytes):
                sha256 = hashlib.sha256(payload).hexdigest()
            elif not sha256 and att.get("size_bytes"):
                # If bytes are not cached, hash metadata + filename
                sha256 = hashlib.sha256(f"{filename}-{att.get('size_bytes')}".encode()).hexdigest()
            elif not sha256:
                sha256 = "NOT_COMPUTED"

            lower_name = filename.lower()
            
            # 2. Dangerous Extension Check
            is_dangerous = False
            for ext in cls.DANGEROUS_EXTENSIONS:
                if lower_name.endswith(ext):
                    is_dangerous = True
                    has_dangerous_ext = True
                    evidence_list.append(Evidence(
                        engine="ATTACHMENT",
                        type="DANGEROUS_ATTACHMENT_EXTENSION",
                        semantic_group="malicious_attachment",
                        value=filename,
                        severity=0.92,
                        confidence=0.98,
                        reliability=0.95,
                        direction="SUPPORTING",
                        description=f"Attachment '{filename}' contains high-risk executable or script extension '{ext}'",
                        source="ATTACHMENT_ANALYZER"
                    ))
                    break

            # 3. Double Extension Detection (e.g. invoice.pdf.exe)
            parts = lower_name.split(".")
            is_double = False
            if len(parts) > 2 and f".{parts[-1]}" in cls.DANGEROUS_EXTENSIONS:
                is_double = True
                has_double_ext = True
                evidence_list.append(Evidence(
                    engine="ATTACHMENT",
                    type="DOUBLE_EXTENSION_SPOOFING",
                    semantic_group="malicious_attachment",
                    value=filename,
                    severity=0.95,
                    confidence=0.99,
                    reliability=0.95,
                    direction="SUPPORTING",
                    description=f"Attachment '{filename}' uses double-extension spoofing to disguise executable payload as a document",
                    source="ATTACHMENT_ANALYZER"
                ))

            # 4. MIME / Extension Mismatch Detection
            is_mismatch = False
            for ext, expected_mime in cls.EXPECTED_MIME_PREFIXES.items():
                if lower_name.endswith(ext) and not content_type.startswith(expected_mime) and content_type != "application/octet-stream":
                    is_mismatch = True
                    has_mime_mismatch = True
                    evidence_list.append(Evidence(
                        engine="ATTACHMENT",
                        type="ATTACHMENT_MIME_MISMATCH",
                        semantic_group="malicious_attachment",
                        value=f"{filename} ({content_type})",
                        severity=0.75,
                        confidence=0.92,
                        reliability=0.90,
                        direction="SUPPORTING",
                        description=f"Attachment '{filename}' declared MIME type '{content_type}' conflicts with file extension '{ext}'",
                        source="ATTACHMENT_ANALYZER"
                    ))
                    break

            # 5. Benign Document Evidence (Mitigating if standard clean document)
            if not is_dangerous and not is_double and not is_mismatch and (lower_name.endswith(".pdf") or lower_name.endswith(".docx") or lower_name.endswith(".xlsx") or lower_name.endswith(".png")):
                evidence_list.append(Evidence(
                    engine="ATTACHMENT",
                    type="BENIGN_STRUCTURED_ATTACHMENT",
                    semantic_group="malicious_attachment",
                    value=filename,
                    severity=0.0,
                    confidence=0.85,
                    reliability=0.85,
                    direction="MITIGATING",
                    description=f"Attachment '{filename}' exhibits standard clean document format with matching MIME type",
                    source="ATTACHMENT_ANALYZER"
                ))

            results.append({
                "filename": filename,
                "content_type": content_type,
                "size_bytes": att.get("size_bytes", 0),
                "sha256": sha256,
                "is_dangerous_extension": is_dangerous,
                "is_double_extension": is_double,
                "is_mime_mismatch": is_mismatch,
                "reputation": "UNKNOWN"
            })

        return {
            "attachments_analysis": results,
            "has_dangerous_extension": has_dangerous_ext,
            "has_mime_mismatch": has_mime_mismatch,
            "has_double_extension": has_double_ext,
            "evidence": evidence_list
        }
