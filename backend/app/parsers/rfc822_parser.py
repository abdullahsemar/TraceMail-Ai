import email
from email import policy
from email.utils import parseaddr, getaddresses
import re
from typing import Dict, Any, List
from app.core.security import sanitize_html

class RFC822Parser:
    @staticmethod
    def parse_raw_bytes(raw_bytes: bytes) -> Dict[str, Any]:
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        headers = {}
        for key, val in msg.items():
            if key in headers:
                if isinstance(headers[key], list):
                    headers[key].append(str(val))
                else:
                    headers[key] = [headers[key], str(val)]
            else:
                headers[key] = str(val)
                
        from_raw = msg.get("From", "")
        display_name, sender_email = parseaddr(from_raw)
        
        to_raw = msg.get_all("To", [])
        to_addresses = [addr for _, addr in getaddresses(to_raw)]
        
        cc_raw = msg.get_all("Cc", [])
        cc_addresses = [addr for _, addr in getaddresses(cc_raw)]
        
        reply_to_raw = msg.get("Reply-To", "")
        _, reply_to_email = parseaddr(reply_to_raw)
        
        return_path_raw = msg.get("Return-Path", "")
        _, return_path_email = parseaddr(return_path_raw)
        
        subject = msg.get("Subject", "")
        date_header = msg.get("Date", "")
        message_id = msg.get("Message-ID", "")
        
        body_text_parts = []
        body_html_parts = []
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                if "attachment" in content_disposition.lower() or part.get_filename():
                    filename = part.get_filename() or "unnamed_attachment"
                    payload = part.get_payload(decode=True) or b""
                    att_sha256 = hashlib.sha256(payload).hexdigest() if payload else ""
                    attachments.append({
                        "filename": filename,
                        "content_type": content_type,
                        "size_bytes": len(payload),
                        "sha256": att_sha256
                    })
                elif content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text_parts.append(payload.decode("utf-8", errors="replace"))
                elif content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_html_parts.append(payload.decode("utf-8", errors="replace"))
        else:
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            if payload:
                decoded = payload.decode("utf-8", errors="replace")
                if content_type == "text/html":
                    body_html_parts.append(decoded)
                else:
                    body_text_parts.append(decoded)
                    
        full_text = "\n".join(body_text_parts)
        full_html = "\n".join(body_html_parts)
        sanitized_html = sanitize_html(full_html)
        
        if not full_text and full_html:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(full_html, "html.parser")
            full_text = soup.get_text(separator="\n").strip()
            
        urls = RFC822Parser.extract_urls(full_text, full_html)
        
        return {
            "subject": subject,
            "message_id": message_id,
            "date": date_header,
            "from_raw": from_raw,
            "sender_display_name": display_name,
            "sender_email": sender_email.lower(),
            "to_addresses": [a.lower() for a in to_addresses],
            "cc_addresses": [a.lower() for a in cc_addresses],
            "reply_to": reply_to_email.lower() if reply_to_email else None,
            "return_path": return_path_email.lower() if return_path_email else None,
            "headers": headers,
            "body_text": full_text,
            "body_html_sanitized": sanitized_html,
            "attachments": attachments,
            "urls": urls
        }
        
    @staticmethod
    def extract_urls(text: str, html: str) -> List[Dict[str, str]]:
        found_urls = []
        seen = set()
        
        if html:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                visible = a.get_text().strip()
                if href and href not in seen:
                    seen.add(href)
                    found_urls.append({
                        "url": href,
                        "visible_text": visible,
                        "source": "HTML_ANCHOR"
                    })
                    
        url_regex = r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s<>"\'()]*)?'
        matches = re.findall(url_regex, text)
        for match in matches:
            if match not in seen:
                seen.add(match)
                found_urls.append({
                    "url": match,
                    "visible_text": match,
                    "source": "PLAIN_TEXT"
                })
                
        return found_urls
