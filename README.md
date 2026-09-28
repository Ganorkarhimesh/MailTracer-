# MailTracer-AI

AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform
(SIH 2026 prototype).

## Architecture

```
mailtracer-ai/
├── backend/
│   ├── app/
│   │   ├── parser.py            # .eml/.msg parsing, headers, hops, SPF/DKIM/DMARC
│   │   ├── geolocation.py       # MaxMind GeoIP2 + Shodan + WHOIS hop intel
│   │   ├── model_inference.py   # DistilBERT + XGBoost + SHAP/LIME threat scoring
│   │   ├── main.py              # FastAPI app (REST + WebSocket)
│   │   ├── schemas.py           # Pydantic request/response models
│   │   └── utils/blockchain_log.py  # optional testnet forensic log receipt
│   ├── requirements.txt
│   └── .env.example
└── frontend/
    ├── src/
    │   ├── components/Dashboard.jsx
    │   ├── pages/index.jsx, _app.jsx
    │   └── styles/globals.css
    ├── package.json
    ├── tailwind.config.js
    └── postcss.config.js
```

## 1. Backend setup (FastAPI)

```bash
cd backend
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
# Edit .env: add SHODAN_API_KEY, MAXMIND_DB_PATH, etc. (optional — the
# platform runs in a graceful offline/heuristic mode without these)

# Download GeoLite2-City.mmdb from https://www.maxmind.com/en/geolite2/signup
# and place it at the path set in MAXMIND_DB_PATH (default ./data/)
mkdir -p data models

uvicorn app.main:app --reload --port 8000
```

Backend will be live at `http://localhost:8000`.
Interactive API docs: `http://localhost:8000/docs`

### Key endpoints
- `POST /api/v1/analyze-email` — multipart upload of a `.eml`/`.msg` file, returns full forensic report
- `WS /ws/live-trace` — real-time hop-by-hop trace stream (send `{"filename": ..., "file_b64": ...}`)
- `GET /api/v1/health` — liveness check

## 2. Frontend setup (Next.js + Tailwind)

```bash
cd frontend
npm install

# point the dashboard at your backend (defaults to localhost:8000)
echo "NEXT_PUBLIC_API_BASE=http://localhost:8000" > .env.local

npm run dev
```

Dashboard will be live at `http://localhost:3000`.

## 3. Optional integrations

| Feature | Env var | Without it |
|---|---|---|
| MaxMind GeoIP2 | `MAXMIND_DB_PATH` | Geolocation fields return `source: "unavailable"` |
| Shodan infra intel | `SHODAN_API_KEY` | Infra risk score omitted, WHOIS/attribution still runs |
| Fine-tuned DistilBERT | `DISTILBERT_MODEL_PATH` | Falls back to keyword-heuristic intent scoring |
| Fine-tuned XGBoost | `XGB_MODEL_PATH` | Falls back to a rule-weighted anomaly score |
| Blockchain log receipt | `BLOCKCHAIN_LOGGING_ENABLED=true` + `TESTNET_RPC_URL` + `WALLET_PRIVATE_KEY` | Returns a `mode: "simulated"` local hash receipt only |

This means the full pipeline (upload → parse → geolocate → score → explain → display)
runs end-to-end out of the box for a demo, and each integration can be
"lit up" incrementally with real credentials/models before judging.

## 4. Training your own models (next steps)

- `model_inference.py` expects a HuggingFace-format DistilBERT sequence
  classifier at `DISTILBERT_MODEL_PATH` with labels
  `["benign", "spam", "phishing", "bec_fraud"]`.
- `model_inference.py` expects an XGBoost `Booster` saved via
  `booster.save_model("xgb_header_anomaly.json")`, trained on the 14
  features listed in `FEATURE_NAMES`.
- Public datasets to bootstrap training: Nazario Phishing Corpus, Enron
  email dataset (benign baseline), CEAS phishing challenge datasets.
