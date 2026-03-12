"""
preprocessing/
Handles raw email ingestion, cleaning, tokenization, and feature extraction.
Feeds normalized representations into downstream analysis layers.
"""

import email
import re
import html
from email.policy import default

def parse_raw_email(raw_email: str) -> dict:
    """Parse a raw email string into headers, body, and attachments."""
    msg = email.message_from_string(raw_email, policy=default)
    
    headers = {k: v for k, v in msg.items()}
    body_parts = []
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get_content_disposition())
            if content_type in ["text/plain", "text/html"] and "attachment" not in content_disposition:
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    body_parts.append(payload.decode(errors="ignore"))
                elif payload:
                    body_parts.append(str(payload))
    else:
        payload = msg.get_payload(decode=True)
        if isinstance(payload, bytes):
            body_parts.append(payload.decode(errors="ignore"))
        elif payload:
            body_parts.append(str(payload))

    body = "".join(body_parts)

    return {
        "headers": headers,
        "body": body,
        "subject": msg.get("Subject", ""),
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
    }

def clean_text(text: str) -> str:
    """Remove noise, normalize whitespace, and sanitize email body text."""
    # Remove HTML tags if present
    text = re.sub(r'<[^>]+>', ' ', text)
    # Unescape HTML entities
    text = html.unescape(text)
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def extract_features(parsed_email: dict) -> dict:
    """Extract NLP and structural features from a parsed email dict."""
    body = parsed_email.get("body", "")
    clean_body = clean_text(body)
    
    # Minimal feature set expected by basic models
    return {
        "clean_body": clean_body,
        "subject_length": len(parsed_email.get("subject", "")),
        "body_length": len(clean_body),
        "has_attachments": False, # Basic placeholder
    }

def tokenize(text: str) -> list:
    """Tokenize cleaned text into a list of tokens."""
    return text.lower().split()
