"""
MailTracer-AI :: AI / ML Threat Detection Engine
-----------------------------------------------------
Combines two models into one 0-100 threat score, returned in <500ms:

  1. DistilBERT (fine-tuned, sequence classification) -> body text /
     subject intent classification (phishing / spam / BEC / benign),
     with a phishing probability in [0, 1].

  2. XGBoost -> structured/header + domain anomaly scoring using
     engineered features (SPF/DKIM/DMARC failures, hop count, domain
     age proxy, envelope mismatch, link/domain mismatch, etc).

Explainability:
  - SHAP TreeExplainer for the XGBoost anomaly model (fast, exact for trees).
  - LIME text explainer for the DistilBERT text model (local, model-agnostic).

Both explanations are collapsed into a short list of human-readable
"risk reasons" the frontend renders directly.

Dependencies: torch, transformers, xgboost, shap, lime, numpy
"""

from __future__ import annotations

import os
import time
import re
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import urlparse

import numpy as np
import xgboost as xgb

try:
    import torch
    from transformers import (
        AutoTokenizer,
        AutoModelForSequenceClassification,
    )
except ImportError:  # pragma: no cover
    torch = None

try:
    import shap
except ImportError:  # pragma: no cover
    shap = None

try:
    from lime.lime_text import LimeTextExplainer
except ImportError:  # pragma: no cover
    LimeTextExplainer = None


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

DISTILBERT_MODEL_PATH = os.getenv(
    "DISTILBERT_MODEL_PATH", "./models/distilbert-phishing-intent"
)
XGB_MODEL_PATH = os.getenv("XGB_MODEL_PATH", "./models/xgb_header_anomaly.json")

LABELS = ["benign", "spam", "phishing", "bec_fraud"]

FEATURE_NAMES = [
    "spf_fail", "dkim_fail", "dmarc_fail",
    "envelope_mismatch", "hop_count", "private_hop_in_chain",
    "num_links", "link_domain_mismatch_count", "has_ip_literal_link",
    "urgent_keyword_count", "subject_all_caps", "attachment_risky_ext",
    "reply_to_mismatch", "shortened_url_count",
]


# --------------------------------------------------------------------------
# Lazy-loaded model singletons (keeps cold start fast, avoids reload per request)
# --------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _load_distilbert():
    if torch is None:
        return None, None
    tokenizer = AutoTokenizer.from_pretrained(DISTILBERT_MODEL_PATH)
    model = AutoModelForSequenceClassification.from_pretrained(DISTILBERT_MODEL_PATH)
    model.eval()
    return tokenizer, model


@lru_cache(maxsize=1)
def _load_xgb() -> xgb.Booster:
    booster = xgb.Booster()
    if os.path.exists(XGB_MODEL_PATH):
        booster.load_model(XGB_MODEL_PATH)
    return booster


# --------------------------------------------------------------------------
# Feature engineering (structured/header signal -> XGBoost input vector)
# --------------------------------------------------------------------------

URGENT_KEYWORDS = [
    "urgent", "verify your account", "suspended", "password expires",
    "click immediately", "confirm your identity", "wire transfer",
    "final notice", "act now", "your account will be closed",
]
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}
RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".jar", ".bat", ".hta", ".lnk"}


def build_feature_vector(parsed_email, links: list[str] | None = None) -> np.ndarray:
    """Builds the XGBoost structured feature vector from a ParsedEmail-like object."""
    links = links or getattr(parsed_email, "links", []) or []
    auth = parsed_email.auth
    subject = parsed_email.subject or ""
    body = parsed_email.body_text or ""

    from_domain = (parsed_email.from_addr or "").split("@")[-1].lower()
    link_domains = [urlparse(l).netloc.lower() for l in links]
    mismatch_count = sum(1 for d in link_domains if d and from_domain and from_domain not in d)
    shortener_count = sum(1 for d in link_domains if d in SHORTENER_DOMAINS)
    ip_literal_links = any(re.match(r"^\d{1,3}(\.\d{1,3}){3}", d) for d in link_domains)

    features = {
        "spf_fail": 1.0 if auth.spf in ("fail", "softfail") else 0.0,
        "dkim_fail": 1.0 if auth.dkim == "fail" else 0.0,
        "dmarc_fail": 1.0 if auth.dmarc == "fail" else 0.0,
        "envelope_mismatch": 1.0 if parsed_email.envelope_mismatch else 0.0,
        "hop_count": float(len(parsed_email.hops)),
        "private_hop_in_chain": 1.0 if any(h.is_private_ip for h in parsed_email.hops) else 0.0,
        "num_links": float(len(links)),
        "link_domain_mismatch_count": float(mismatch_count),
        "has_ip_literal_link": 1.0 if ip_literal_links else 0.0,
        "urgent_keyword_count": float(sum(1 for kw in URGENT_KEYWORDS if kw in body.lower())),
        "subject_all_caps": 1.0 if subject.isupper() and len(subject) > 4 else 0.0,
        "attachment_risky_ext": 1.0 if any(
            any(a.lower().endswith(ext) for ext in RISKY_EXTENSIONS)
            for a in (parsed_email.attachments or [])
        ) else 0.0,
        "reply_to_mismatch": 1.0 if (
            parsed_email.reply_to and parsed_email.reply_to != parsed_email.from_addr
        ) else 0.0,
        "shortened_url_count": float(shortener_count),
    }
    return np.array([features[name] for name in FEATURE_NAMES], dtype=np.float32)


# --------------------------------------------------------------------------
# Model inference
# --------------------------------------------------------------------------

@dataclass
class TextIntentResult:
    label: str
    phishing_probability: float
    class_probabilities: dict[str, float]


def classify_text_intent(subject: str, body: str) -> TextIntentResult:
    tokenizer, model = _load_distilbert()
    text = f"{subject}\n\n{body}"[:2000]

    if tokenizer is None or model is None:
        # Graceful offline fallback: heuristic keyword scoring so the API
        # still returns a usable result without GPU/model weights present.
        hits = sum(1 for kw in URGENT_KEYWORDS if kw in text.lower())
        prob = min(0.15 + hits * 0.15, 0.95)
        probs = {"benign": 1 - prob, "spam": prob * 0.3, "phishing": prob * 0.6, "bec_fraud": prob * 0.1}
        return TextIntentResult(label="phishing" if prob > 0.5 else "benign",
                                 phishing_probability=round(prob, 4),
                                 class_probabilities={k: round(v, 4) for k, v in probs.items()})

    with torch.no_grad():
        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=256)
        logits = model(**inputs).logits
        probs = torch.softmax(logits, dim=-1).squeeze().tolist()

    class_probs = dict(zip(LABELS, probs))
    top_label = max(class_probs, key=class_probs.get)
    phishing_prob = class_probs.get("phishing", 0.0) + class_probs.get("bec_fraud", 0.0)

    return TextIntentResult(
        label=top_label,
        phishing_probability=round(phishing_prob, 4),
        class_probabilities={k: round(v, 4) for k, v in class_probs.items()},
    )


def score_header_anomaly(feature_vector: np.ndarray) -> float:
    """Returns XGBoost anomaly probability in [0, 1]. Falls back to a rule-based score."""
    booster = _load_xgb()
    try:
        dmatrix = xgb.DMatrix(feature_vector.reshape(1, -1), feature_names=FEATURE_NAMES)
        pred = booster.predict(dmatrix)
        return float(pred[0])
    except Exception:
        # Fallback: weighted linear rule if no trained booster is loaded yet
        weights = np.array([0.15, 0.1, 0.15, 0.1, 0.02, 0.08, 0.02, 0.1, 0.08, 0.1, 0.03, 0.15, 0.1, 0.05])
        weights = weights[: len(feature_vector)]
        score = float(np.dot(feature_vector, weights) / (weights.sum() or 1))
        return min(max(score, 0.0), 1.0)


# --------------------------------------------------------------------------
# Explainability: SHAP (structured) + LIME (text)
# --------------------------------------------------------------------------

def explain_header_anomaly(feature_vector: np.ndarray, top_k: int = 4) -> list[str]:
    booster = _load_xgb()
    reasons = []
    try:
        if shap is None:
            raise RuntimeError("shap not installed")
        explainer = shap.TreeExplainer(booster)
        shap_values = explainer.shap_values(feature_vector.reshape(1, -1))[0]
        ranked = sorted(zip(FEATURE_NAMES, shap_values), key=lambda x: -abs(x[1]))[:top_k]
        for name, val in ranked:
            if abs(val) < 1e-3:
                continue
            reasons.append(_humanize_feature(name, val))
    except Exception:
        # Fallback: rank by raw feature magnitude if SHAP/model unavailable
        ranked = sorted(zip(FEATURE_NAMES, feature_vector), key=lambda x: -x[1])[:top_k]
        for name, val in ranked:
            if val <= 0:
                continue
            reasons.append(_humanize_feature(name, val))
    return reasons


def _humanize_feature(name: str, value: float) -> str:
    direction = "increased" if value > 0 else "decreased"
    mapping = {
        "spf_fail": "SPF authentication failed for the sending domain",
        "dkim_fail": "DKIM signature validation failed",
        "dmarc_fail": "DMARC policy check failed",
        "envelope_mismatch": "Reply-To / Return-Path address differs from the visible From address",
        "hop_count": "Unusually long relay/hop chain",
        "private_hop_in_chain": "A private/internal IP appears in the public relay chain (possible spoofing)",
        "num_links": "Message contains a high number of embedded links",
        "link_domain_mismatch_count": "Embedded links point to domains unrelated to the sender's domain",
        "has_ip_literal_link": "A link uses a raw IP address instead of a domain name",
        "urgent_keyword_count": "Body text uses urgency/pressure language typical of phishing",
        "subject_all_caps": "Subject line is in all caps, a common spam signal",
        "attachment_risky_ext": "Attachment has a high-risk executable file extension",
        "reply_to_mismatch": "Reply-To address does not match the sender address",
        "shortened_url_count": "Message uses URL shortening services, which can mask the true destination",
    }
    return mapping.get(name, f"Feature '{name}' {direction} the anomaly score")


def explain_text_intent(subject: str, body: str, top_k: int = 4) -> list[str]:
    tokenizer, model = _load_distilbert()
    text = f"{subject}\n\n{body}"[:1000]

    if LimeTextExplainer is None or tokenizer is None or model is None:
        hits = [kw for kw in URGENT_KEYWORDS if kw in text.lower()][:top_k]
        return [f'Body text contains phishing-associated phrase: "{kw}"' for kw in hits]

    def predict_proba(texts: list[str]) -> np.ndarray:
        with torch.no_grad():
            batch = tokenizer(texts, return_tensors="pt", truncation=True,
                               max_length=256, padding=True)
            logits = model(**batch).logits
            return torch.softmax(logits, dim=-1).numpy()

    explainer = LimeTextExplainer(class_names=LABELS)
    try:
        exp = explainer.explain_instance(
            text, predict_proba, num_features=top_k, labels=(LABELS.index("phishing"),)
        )
        weighted_words = exp.as_list(label=LABELS.index("phishing"))
        return [
            f'The phrase "{word}" strongly influenced the phishing classification'
            for word, weight in weighted_words if weight > 0
        ]
    except Exception:
        return []


# --------------------------------------------------------------------------
# Combined public entrypoint
# --------------------------------------------------------------------------

@dataclass
class ThreatAssessment:
    threat_score: int              # 0-100 final combined score
    risk_level: str                # low / medium / high / critical
    text_intent: TextIntentResult
    header_anomaly_probability: float
    reasons: list[str]
    latency_ms: float


def _risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def assess_threat(parsed_email, weight_text: float = 0.6, weight_header: float = 0.4) -> ThreatAssessment:
    """
    Main entrypoint used by the API layer. Combines DistilBERT text intent
    and XGBoost header/domain anomaly scores into one 0-100 threat score,
    with SHAP + LIME derived human-readable reasons. Target latency: <500ms
    on CPU for typical email sizes.
    """
    start = time.perf_counter()

    text_result = classify_text_intent(parsed_email.subject or "", parsed_email.body_text or "")
    feature_vector = build_feature_vector(parsed_email)
    header_anomaly_prob = score_header_anomaly(feature_vector)

    combined = weight_text * text_result.phishing_probability + weight_header * header_anomaly_prob
    threat_score = int(round(min(max(combined, 0.0), 1.0) * 100))

    reasons = explain_header_anomaly(feature_vector) + explain_text_intent(
        parsed_email.subject or "", parsed_email.body_text or ""
    )
    reasons = reasons[:6] if reasons else ["No strong risk indicators detected."]

    latency_ms = (time.perf_counter() - start) * 1000

    return ThreatAssessment(
        threat_score=threat_score,
        risk_level=_risk_level(threat_score),
        text_intent=text_result,
        header_anomaly_probability=round(header_anomaly_prob, 4),
        reasons=reasons,
        latency_ms=round(latency_ms, 2),
    )
