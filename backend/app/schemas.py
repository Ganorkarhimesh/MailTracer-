"""
MailTracer-AI :: API response/request schemas (Pydantic v2)
"""

from __future__ import annotations
from typing import Optional
from pydantic import BaseModel


class HopSchema(BaseModel):
    hop_index: int
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    ip: Optional[str] = None
    is_private_ip: bool = False
    protocol: Optional[str] = None
    timestamp: Optional[str] = None
    geo: Optional[dict] = None
    shodan: Optional[dict] = None
    whois: Optional[dict] = None
    combined_risk_score: Optional[float] = None


class AuthSchema(BaseModel):
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dkim_domain: Optional[str] = None
    dmarc: Optional[str] = None


class ThreatSchema(BaseModel):
    threat_score: int
    risk_level: str
    text_label: str
    phishing_probability: float
    header_anomaly_probability: float
    reasons: list[str]
    latency_ms: float


class BlockchainReceiptSchema(BaseModel):
    enabled: bool
    report_hash: str
    tx_hash: Optional[str] = None
    network: Optional[str] = None
    mode: str


class AnalyzeEmailResponse(BaseModel):
    filename: str
    message_id: Optional[str] = None
    subject: Optional[str] = None
    from_addr: Optional[str] = None
    reply_to: Optional[str] = None
    to_addrs: list[str] = []
    date: Optional[str] = None
    envelope_mismatch: bool = False
    auth: AuthSchema
    hops: list[HopSchema]
    links: list[str] = []
    attachments: list[str] = []
    threat: ThreatSchema
    blockchain_receipt: Optional[BlockchainReceiptSchema] = None


class LiveTraceMessage(BaseModel):
    type: str            # "hop_start" | "hop_result" | "done" | "error"
    hop_index: Optional[int] = None
    total_hops: Optional[int] = None
    data: Optional[dict] = None
    message: Optional[str] = None
