"""
MailTracer-AI :: FastAPI Backend
------------------------------------
Endpoints:
  POST /api/v1/analyze-email   - multipart .eml/.msg upload -> full forensic report
  WS   /ws/live-trace          - real-time hop-by-hop tracing status stream
  GET  /api/v1/health          - liveness probe

Run:
  uvicorn app.main:app --reload --port 8000
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app import parser as email_parser
from app import geolocation
from app import model_inference
from app.utils.blockchain_log import anchor_report, receipt_to_dict
from app.schemas import (
    AnalyzeEmailResponse, HopSchema, AuthSchema, ThreatSchema, BlockchainReceiptSchema,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mailtracer")

app = FastAPI(
    title="MailTracer-AI",
    description="AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ALLOWED_EXTENSIONS = (".eml", ".msg")
MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB


@app.get("/api/v1/health")
async def health():
    return {"status": "ok", "service": "mailtracer-ai", "time": datetime.utcnow().isoformat()}


def _build_report(filename: str, raw_bytes: bytes) -> dict:
    """Shared pipeline used by both the REST endpoint and the WS trace endpoint."""
    parsed = email_parser.parse_file(filename, raw_bytes)
    hop_intel = geolocation.trace_hops(parsed.hop_ips)
    intel_by_ip = {h["ip"]: h for h in hop_intel}

    assessment = model_inference.assess_threat(parsed)

    hops_out = []
    for hop in parsed.hops:
        intel = intel_by_ip.get(hop.ip) if hop.ip else None
        hops_out.append(HopSchema(
            hop_index=hop.hop_index,
            from_host=hop.from_host,
            by_host=hop.by_host,
            ip=hop.ip,
            is_private_ip=hop.is_private_ip,
            protocol=hop.protocol,
            timestamp=hop.timestamp.isoformat() if hop.timestamp else None,
            geo=intel["geo"] if intel else None,
            shodan=intel["shodan"] if intel else None,
            whois=intel["whois"] if intel else None,
            combined_risk_score=intel["combined_risk_score"] if intel else None,
        ))

    threat_schema = ThreatSchema(
        threat_score=assessment.threat_score,
        risk_level=assessment.risk_level,
        text_label=assessment.text_intent.label,
        phishing_probability=assessment.text_intent.phishing_probability,
        header_anomaly_probability=assessment.header_anomaly_probability,
        reasons=assessment.reasons,
        latency_ms=assessment.latency_ms,
    )

    response = AnalyzeEmailResponse(
        filename=filename,
        message_id=parsed.message_id,
        subject=parsed.subject,
        from_addr=parsed.from_addr,
        reply_to=parsed.reply_to,
        to_addrs=parsed.to_addrs,
        date=parsed.date,
        envelope_mismatch=parsed.envelope_mismatch,
        auth=AuthSchema(
            spf=parsed.auth.spf, dkim=parsed.auth.dkim,
            dkim_domain=parsed.auth.dkim_domain, dmarc=parsed.auth.dmarc,
        ),
        hops=hops_out,
        links=parsed.links,
        attachments=parsed.attachments,
        threat=threat_schema,
    )

    report_dict = response.model_dump()
    receipt = anchor_report(report_dict)
    response.blockchain_receipt = BlockchainReceiptSchema(**receipt_to_dict(receipt))
    return response


@app.post("/api/v1/analyze-email", response_model=AnalyzeEmailResponse)
async def analyze_email(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(ALLOWED_EXTENSIONS):
        raise HTTPException(status_code=400, detail="Only .eml or .msg files are supported.")

    raw_bytes = await file.read()
    if len(raw_bytes) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds 25MB limit.")
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    try:
        return _build_report(file.filename, raw_bytes)
    except Exception as exc:
        logger.exception("Analysis failed for %s", file.filename)
        raise HTTPException(status_code=422, detail=f"Failed to analyze email: {exc}")


# --------------------------------------------------------------------------
# WebSocket: real-time hop-by-hop trace status
# --------------------------------------------------------------------------

@app.websocket("/ws/live-trace")
async def live_trace(websocket: WebSocket):
    """
    Client sends: {"filename": "sample.eml", "file_b64": "<base64 raw bytes>"}
    Server streams: hop_start -> hop_result (per hop) -> done, or error.
    """
    await websocket.accept()
    try:
        payload = await websocket.receive_json()
        filename = payload.get("filename", "upload.eml")
        file_b64 = payload.get("file_b64")
        if not file_b64:
            await websocket.send_json({"type": "error", "message": "file_b64 is required"})
            await websocket.close()
            return

        import base64
        raw_bytes = base64.b64decode(file_b64)
        parsed = email_parser.parse_file(filename, raw_bytes)

        total_hops = len(parsed.hop_ips)
        await websocket.send_json({"type": "meta", "total_hops": total_hops, "subject": parsed.subject})

        for idx, ip in enumerate(parsed.hop_ips):
            await websocket.send_json({"type": "hop_start", "hop_index": idx, "total_hops": total_hops})
            # Simulate incremental network latency per lookup so the UI can
            # animate hop-by-hop instead of receiving everything at once.
            await asyncio.sleep(0.05)
            intel = await asyncio.to_thread(geolocation.trace_hop, ip)
            await websocket.send_json({
                "type": "hop_result",
                "hop_index": idx,
                "total_hops": total_hops,
                "data": intel,
            })

        assessment = await asyncio.to_thread(model_inference.assess_threat, parsed)
        await websocket.send_json({
            "type": "done",
            "data": {
                "threat_score": assessment.threat_score,
                "risk_level": assessment.risk_level,
                "reasons": assessment.reasons,
            },
        })

    except WebSocketDisconnect:
        logger.info("Client disconnected from /ws/live-trace")
    except Exception as exc:
        logger.exception("live-trace error")
        try:
            await websocket.send_json({"type": "error", "message": str(exc)})
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
