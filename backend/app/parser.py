"""
MailTracer-AI :: Email Parsing & Threat Intel Engine
------------------------------------------------------
Parses raw .eml (RFC 822/MIME) and .msg (Outlook binary) files into a
normalized structure: headers, SMTP relay/hop chain, hop IPs,
SPF/DKIM/DMARC authentication results, body text, and extracted links.

Dependencies: extract-msg (for .msg), python (email, re, ipaddress stdlib)
"""

from __future__ import annotations

import re
import ipaddress
import email
import email.policy
from email.message import Message
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

# extract-msg is only needed for legacy Outlook .msg files
try:
    import extract_msg  # type: ignore
except ImportError:  # pragma: no cover
    extract_msg = None


# --------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------

@dataclass
class HopRecord:
    hop_index: int
    raw_received_header: str
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    ip: Optional[str] = None
    is_private_ip: bool = False
    timestamp: Optional[datetime] = None
    protocol: Optional[str] = None  # ESMTP / SMTP / ESMTPS


@dataclass
class AuthResult:
    spf: Optional[str] = None          # pass / fail / softfail / neutral / none
    spf_raw: Optional[str] = None
    dkim: Optional[str] = None         # pass / fail / none
    dkim_domain: Optional[str] = None
    dkim_raw: Optional[str] = None
    dmarc: Optional[str] = None        # pass / fail / none
    dmarc_raw: Optional[str] = None


@dataclass
class ParsedEmail:
    message_id: Optional[str]
    subject: Optional[str]
    from_addr: Optional[str]
    reply_to: Optional[str]
    to_addrs: list[str]
    date: Optional[str]
    headers: dict[str, str]
    hops: list[HopRecord]
    hop_ips: list[str]
    auth: AuthResult
    body_text: str
    body_html: Optional[str]
    links: list[str]
    attachments: list[str]
    envelope_mismatch: bool = False  # From vs Reply-To / Return-Path mismatch


# --------------------------------------------------------------------------
# Regex helpers
# --------------------------------------------------------------------------

IP_REGEX = re.compile(
    r"(?<![\w.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\w.])"
)
IPV6_REGEX = re.compile(r"(?<![\w:])([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w:])")
URL_REGEX = re.compile(r"https?://[^\s\"'<>()]+", re.IGNORECASE)

RECEIVED_FROM_RE = re.compile(r"from\s+([^\s]+(?:\s+\([^)]*\))?)", re.IGNORECASE)
RECEIVED_BY_RE = re.compile(r"\bby\s+([^\s]+)", re.IGNORECASE)
RECEIVED_PROTO_RE = re.compile(r"\bwith\s+(E?SMTPS?A?)\b", re.IGNORECASE)
RECEIVED_DATE_RE = re.compile(r";\s*(.+)$")


def _extract_ip(text: str) -> Optional[str]:
    m = IP_REGEX.search(text)
    if m:
        return m.group(1)
    m6 = IPV6_REGEX.search(text)
    if m6:
        try:
            ipaddress.IPv6Address(m6.group(1))
            return m6.group(1)
        except ValueError:
            return None
    return None


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _parse_received_header(idx: int, raw: str) -> HopRecord:
    hop = HopRecord(hop_index=idx, raw_received_header=raw)

    from_match = RECEIVED_FROM_RE.search(raw)
    if from_match:
        hop.from_host = from_match.group(1).strip()

    by_match = RECEIVED_BY_RE.search(raw)
    if by_match:
        hop.by_host = by_match.group(1).strip()

    proto_match = RECEIVED_PROTO_RE.search(raw)
    if proto_match:
        hop.protocol = proto_match.group(1).upper()

    ip = _extract_ip(raw)
    if ip:
        hop.ip = ip
        hop.is_private_ip = _is_private(ip)

    date_match = RECEIVED_DATE_RE.search(raw)
    if date_match:
        try:
            hop.timestamp = email.utils.parsedate_to_datetime(date_match.group(1).strip())
        except Exception:
            hop.timestamp = None

    return hop


def _parse_auth_results(msg: Message) -> AuthResult:
    """Parses Authentication-Results / Received-SPF headers for SPF/DKIM/DMARC."""
    result = AuthResult()

    auth_headers = msg.get_all("Authentication-Results") or []
    combined = " ".join(auth_headers)

    spf_m = re.search(r"spf=(\w+)", combined, re.IGNORECASE)
    if spf_m:
        result.spf = spf_m.group(1).lower()
        result.spf_raw = combined

    dkim_m = re.search(r"dkim=(\w+)", combined, re.IGNORECASE)
    if dkim_m:
        result.dkim = dkim_m.group(1).lower()
        result.dkim_raw = combined
        dkim_domain_m = re.search(r"header\.d=([\w.\-]+)", combined, re.IGNORECASE)
        if dkim_domain_m:
            result.dkim_domain = dkim_domain_m.group(1)

    dmarc_m = re.search(r"dmarc=(\w+)", combined, re.IGNORECASE)
    if dmarc_m:
        result.dmarc = dmarc_m.group(1).lower()
        result.dmarc_raw = combined

    # Fallback: legacy Received-SPF header
    if result.spf is None:
        spf_header = msg.get("Received-SPF")
        if spf_header:
            m = re.match(r"(\w+)", spf_header.strip())
            if m:
                result.spf = m.group(1).lower()
                result.spf_raw = spf_header

    return result


def _extract_links(text: str) -> list[str]:
    return sorted(set(URL_REGEX.findall(text or "")))


def _get_body(msg: Message) -> tuple[str, Optional[str]]:
    """Returns (plain_text, html) bodies, walking multipart MIME trees."""
    text_body, html_body = "", None

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition") or "")
            if "attachment" in disposition:
                continue
            try:
                payload = part.get_content()
            except Exception:
                continue
            if content_type == "text/plain" and not text_body:
                text_body = payload
            elif content_type == "text/html" and not html_body:
                html_body = payload
    else:
        try:
            payload = msg.get_content()
        except Exception:
            payload = ""
        if msg.get_content_type() == "text/html":
            html_body = payload
        else:
            text_body = payload

    return text_body or "", html_body


def _get_attachments(msg: Message) -> list[str]:
    names = []
    if msg.is_multipart():
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                names.append(filename)
    return names


def _check_envelope_mismatch(msg: Message) -> bool:
    from_addr = email.utils.parseaddr(msg.get("From", ""))[1].lower()
    reply_to = email.utils.parseaddr(msg.get("Reply-To", ""))[1].lower()
    return_path = email.utils.parseaddr(msg.get("Return-Path", ""))[1].lower()

    candidates = [a for a in (reply_to, return_path) if a]
    return any(a and a != from_addr for a in candidates)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def parse_eml_bytes(raw_bytes: bytes) -> ParsedEmail:
    """Parses raw .eml bytes into a normalized ParsedEmail object."""
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    return _parse_message(msg)


def parse_msg_bytes(raw_bytes: bytes, tmp_path: str = "/tmp/_mailtracer_upload.msg") -> ParsedEmail:
    """Parses legacy Outlook .msg bytes by converting to an email.message.Message-like structure."""
    if extract_msg is None:
        raise RuntimeError(
            "extract-msg is not installed. Run `pip install extract-msg` to enable .msg support."
        )
    with open(tmp_path, "wb") as f:
        f.write(raw_bytes)

    m = extract_msg.Message(tmp_path)
    headers_text = m.header if m.header else ""
    if headers_text:
        msg = email.message_from_string(headers_text, policy=email.policy.default)
    else:
        msg = email.message.EmailMessage(policy=email.policy.default)
        msg["From"] = m.sender or ""
        msg["To"] = m.to or ""
        msg["Subject"] = m.subject or ""
        msg["Date"] = m.date or ""

    parsed = _parse_message(msg)
    # extract-msg gives us reliable body text directly
    parsed.body_text = m.body or parsed.body_text
    parsed.links = _extract_links(parsed.body_text)
    parsed.attachments = [a.longFilename or a.shortFilename for a in (m.attachments or [])]
    m.close()
    return parsed


def _parse_message(msg: Message) -> ParsedEmail:
    headers = {k: v for k, v in msg.items()}

    received_headers = msg.get_all("Received") or []
    # Received headers appear newest-first in raw email; reverse for chronological hop order
    hops = [
        _parse_received_header(i, raw)
        for i, raw in enumerate(reversed(received_headers))
    ]
    hop_ips = [h.ip for h in hops if h.ip and not h.is_private_ip]

    auth = _parse_auth_results(msg)
    body_text, body_html = _get_body(msg)
    links = _extract_links(body_text) + _extract_links(body_html or "")

    to_addrs = [addr for _, addr in email.utils.getaddresses(msg.get_all("To", []))]

    return ParsedEmail(
        message_id=msg.get("Message-ID"),
        subject=msg.get("Subject"),
        from_addr=email.utils.parseaddr(msg.get("From", ""))[1],
        reply_to=email.utils.parseaddr(msg.get("Reply-To", ""))[1] or None,
        to_addrs=to_addrs,
        date=msg.get("Date"),
        headers=headers,
        hops=hops,
        hop_ips=sorted(set(hop_ips), key=hop_ips.index),
        auth=auth,
        body_text=body_text,
        body_html=body_html,
        links=sorted(set(links)),
        attachments=_get_attachments(msg),
        envelope_mismatch=_check_envelope_mismatch(msg),
    )


def parse_file(filename: str, raw_bytes: bytes) -> ParsedEmail:
    """Dispatches to the correct parser based on file extension."""
    lower = filename.lower()
    if lower.endswith(".msg"):
        return parse_msg_bytes(raw_bytes)
    return parse_eml_bytes(raw_bytes)
