import re
from bs4 import BeautifulSoup

def sanitize_html(raw_html: str) -> str:
    if not raw_html:
        return ""
    
    soup = BeautifulSoup(raw_html, "html.parser")
    for tag in soup(["script", "style", "iframe", "object", "embed", "applet", "form", "meta", "link"]):
        tag.decompose()
        
    for tag in soup.find_all(True):
        attrs = dict(tag.attrs)
        for attr, val in attrs.items():
            if attr.lower().startswith("on"):
                del tag.attrs[attr]
            elif attr.lower() in ["href", "src", "action"]:
                if isinstance(val, str) and (val.strip().lower().startswith("javascript:") or val.strip().lower().startswith("data:")):
                    del tag.attrs[attr]
                    
    return str(soup)

def mask_sensitive_data(text: str, role: str = "SOC_ANALYST") -> str:
    if not text:
        return ""
    if role == "ADMIN":
        return text
    text = re.sub(r'\b(?:\d[ -]*?){13,16}\b', '[REDACTED_PAYMENT_INFO]', text)
    text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED_SSN]', text)
    return text
