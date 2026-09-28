import React, { useCallback, useRef, useState } from "react";

/**
 * MailTracer-AI :: Forensic Analyst Dashboard
 * ------------------------------------------------
 * Design intent: a SOC (Security Operations Center) console, not a generic
 * SaaS card grid. Near-black slate background, a single signal accent
 * (amber -> red as threat rises), monospace for IPs/hashes/scores because
 * that's how analysts actually read this data, and a left "case file"
 * column paired with a right "evidence" column rather than stacked cards.
 *
 * Backend contract: POST /api/v1/analyze-email (multipart "file")
 * Response shape matches backend/app/schemas.py::AnalyzeEmailResponse
 */

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

const RISK_COLORS = {
  low: { ring: "#3FB88A", text: "text-emerald-400", bg: "bg-emerald-500/10" },
  medium: { ring: "#E8B93F", text: "text-amber-400", bg: "bg-amber-500/10" },
  high: { ring: "#E8722F", text: "text-orange-400", bg: "bg-orange-500/10" },
  critical: { ring: "#D64545", text: "text-red-400", bg: "bg-red-500/10" },
};

function riskFromScore(score) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

/* ---------------------------------------------------------------------- */
/* Threat Score Dial                                                       */
/* ---------------------------------------------------------------------- */

function ThreatDial({ score }) {
  const level = riskFromScore(score);
  const color = RISK_COLORS[level].ring;
  const radius = 72;
  const circumference = 2 * Math.PI * radius;
  const filled = (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center">
      <svg width="180" height="180" viewBox="0 0 180 180" className="-rotate-90">
        <circle cx="90" cy="90" r={radius} fill="none" stroke="#1E2530" strokeWidth="14" />
        <circle
          cx="90" cy="90" r={radius} fill="none"
          stroke={color} strokeWidth="14" strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference - filled}`}
          style={{ transition: "stroke-dasharray 700ms ease-out" }}
        />
      </svg>
      <div className="-mt-[122px] flex flex-col items-center">
        <span className="font-mono text-5xl font-semibold text-slate-100 tabular-nums">
          {score}
        </span>
        <span className="text-xs tracking-wide text-slate-500">/ 100</span>
      </div>
      <div className="mt-8">
        <span className={`rounded px-3 py-1 font-mono text-xs uppercase ${RISK_COLORS[level].bg} ${RISK_COLORS[level].text}`}>
          {level} risk
        </span>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------------- */
/* Drag & Drop Uploader                                                    */
/* ---------------------------------------------------------------------- */

function Uploader({ onFileSelected, isLoading }) {
  const [isDragging, setIsDragging] = useState(false);
  const inputRef = useRef(null);

  const handleFiles = useCallback((files) => {
    const file = files?.[0];
    if (!file) return;
    const lower = file.name.toLowerCase();
    if (!lower.endsWith(".eml") && !lower.endsWith(".msg")) {
      alert("Only .eml or .msg files are supported.");
      return;
    }
    onFileSelected(file);
  }, [onFileSelected]);

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={(e) => { e.preventDefault(); setIsDragging(false); handleFiles(e.dataTransfer.files); }}
      onClick={() => inputRef.current?.click()}
      className={`flex cursor-pointer flex-col items-center justify-center rounded-md border-2 border-dashed px-6 py-14 text-center transition-colors
        ${isDragging ? "border-amber-400 bg-amber-500/5" : "border-slate-700 hover:border-slate-500"}`}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".eml,.msg"
        className="hidden"
        onChange={(e) => handleFiles(e.target.files)}
      />
      <svg width="34" height="34" viewBox="0 0 24 24" fill="none" className="mb-4 text-slate-500">
        <path d="M12 3v12m0-12 4 4m-4-4-4 4M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"
          stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <p className="font-mono text-sm text-slate-300">
        {isLoading ? "Analyzing..." : "Drop .eml or .msg file here"}
      </p>
      <p className="mt-1 text-xs text-slate-500">or click to browse — max 25MB</p>
    </div>
  );
}

/* ---------------------------------------------------------------------- */
/* Hop-by-hop routing map                                                  */
/* ---------------------------------------------------------------------- */

function HopMap({ hops }) {
  if (!hops?.length) {
    return <p className="text-sm text-slate-500">No public relay hops found in this message.</p>;
  }
  return (
    <ol className="relative border-l border-slate-700 pl-6">
      {hops.map((hop, i) => {
        const risk = hop.combined_risk_score ?? 0;
        const level = riskFromScore(risk);
        return (
          <li key={i} className="mb-6 last:mb-0">
            <span
              className="absolute -left-[7px] mt-1.5 h-3 w-3 rounded-full border-2 border-slate-900"
              style={{ background: RISK_COLORS[level].ring }}
            />
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <span className="font-mono text-sm text-slate-200">
                {hop.ip || "internal / no IP"}
              </span>
              {hop.ip && (
                <span className={`font-mono text-xs ${RISK_COLORS[level].text}`}>
                  risk {risk.toFixed?.(0) ?? risk}
                </span>
              )}
            </div>
            <p className="mt-0.5 text-xs text-slate-500">
              {hop.geo?.city || "Unknown city"}
              {hop.geo?.country ? `, ${hop.geo.country}` : ""}
              {hop.whois?.asn_description ? ` — ${hop.whois.asn_description}` : ""}
            </p>
            {hop.from_host && (
              <p className="mt-0.5 truncate text-xs text-slate-600">from {hop.from_host}</p>
            )}
          </li>
        );
      })}
    </ol>
  );
}

/* ---------------------------------------------------------------------- */
/* Explainable threat breakdown                                            */
/* ---------------------------------------------------------------------- */

function ExplainabilityPanel({ threat, auth }) {
  const authRows = [
    { label: "SPF", value: auth?.spf },
    { label: "DKIM", value: auth?.dkim },
    { label: "DMARC", value: auth?.dmarc },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h3 className="mb-2 font-mono text-xs uppercase tracking-wide text-slate-500">
          Authentication
        </h3>
        <div className="grid grid-cols-3 gap-2">
          {authRows.map((row) => {
            const pass = row.value === "pass";
            const fail = row.value === "fail" || row.value === "softfail";
            return (
              <div key={row.label} className="rounded border border-slate-800 bg-slate-900/60 p-3 text-center">
                <p className="text-[10px] uppercase text-slate-500">{row.label}</p>
                <p className={`mt-1 font-mono text-sm ${pass ? "text-emerald-400" : fail ? "text-red-400" : "text-slate-400"}`}>
                  {row.value || "n/a"}
                </p>
              </div>
            );
          })}
        </div>
      </div>

      <div>
        <h3 className="mb-2 font-mono text-xs uppercase tracking-wide text-slate-500">
          Why this score — model-derived reasons
        </h3>
        <ul className="space-y-2">
          {(threat?.reasons || []).map((reason, i) => (
            <li key={i} className="flex gap-2 rounded border border-slate-800 bg-slate-900/60 p-3 text-sm text-slate-300">
              <span className="mt-0.5 font-mono text-xs text-amber-400">{String(i + 1).padStart(2, "0")}</span>
              {reason}
            </li>
          ))}
        </ul>
      </div>

      <div className="flex gap-4 text-xs text-slate-500">
        <span>Text intent: <span className="text-slate-300">{threat?.text_label}</span></span>
        <span>Phishing prob: <span className="text-slate-300">{(threat?.phishing_probability * 100).toFixed(1)}%</span></span>
        <span>Inference: <span className="text-slate-300">{threat?.latency_ms} ms</span></span>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------------- */
/* Main Dashboard                                                          */
/* ---------------------------------------------------------------------- */

export default function Dashboard() {
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  const analyzeFile = useCallback(async (file) => {
    setIsLoading(true);
    setError(null);
    setReport(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await fetch(`${API_BASE}/api/v1/analyze-email`, {
        method: "POST",
        body: formData,
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `Analysis failed (${res.status})`);
      }
      const data = await res.json();
      setReport(data);
    } catch (err) {
      setError(err.message || "Something went wrong while analyzing the email.");
    } finally {
      setIsLoading(false);
    }
  }, []);

  return (
    <div className="min-h-screen bg-[#0B0F14] text-slate-100">
      <header className="border-b border-slate-800 px-8 py-5">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="font-mono text-lg font-semibold tracking-tight">MailTracer&nbsp;AI</h1>
            <p className="text-xs text-slate-500">Email threat detection &amp; forensic intelligence</p>
          </div>
          {report?.blockchain_receipt && (
            <div className="text-right text-xs text-slate-500">
              <p>Report hash</p>
              <p className="font-mono text-slate-400">
                {report.blockchain_receipt.report_hash.slice(0, 18)}…
              </p>
            </div>
          )}
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-8 py-10">
        {!report && (
          <div className="mx-auto max-w-xl">
            <Uploader onFileSelected={analyzeFile} isLoading={isLoading} />
            {error && (
              <p className="mt-4 rounded border border-red-900 bg-red-950/40 p-3 text-sm text-red-400">
                {error}
              </p>
            )}
          </div>
        )}

        {report && (
          <div className="grid grid-cols-1 gap-8 lg:grid-cols-[320px_1fr]">
            {/* Left: case summary + dial */}
            <div className="space-y-6">
              <div className="rounded-md border border-slate-800 bg-slate-900/40 p-6">
                <ThreatDial score={report.threat.threat_score} />
              </div>
              <div className="rounded-md border border-slate-800 bg-slate-900/40 p-5 text-sm">
                <p className="mb-1 text-xs uppercase tracking-wide text-slate-500">Subject</p>
                <p className="mb-4 text-slate-200">{report.subject || "(no subject)"}</p>
                <p className="mb-1 text-xs uppercase tracking-wide text-slate-500">From</p>
                <p className="mb-4 font-mono text-slate-300">{report.from_addr}</p>
                <p className="mb-1 text-xs uppercase tracking-wide text-slate-500">Date</p>
                <p className="font-mono text-slate-300">{report.date}</p>
                {report.envelope_mismatch && (
                  <p className="mt-4 rounded bg-amber-500/10 px-3 py-2 text-xs text-amber-400">
                    Reply-To / Return-Path mismatch detected
                  </p>
                )}
              </div>
              <button
                onClick={() => { setReport(null); setError(null); }}
                className="w-full rounded border border-slate-700 py-2 text-sm text-slate-400 hover:border-slate-500 hover:text-slate-200"
              >
                Analyze another email
              </button>
            </div>

            {/* Right: hop map + explainability */}
            <div className="space-y-8">
              <section className="rounded-md border border-slate-800 bg-slate-900/40 p-6">
                <h2 className="mb-5 font-mono text-sm text-slate-300">Relay chain &amp; hop geolocation</h2>
                <HopMap hops={report.hops} />
              </section>

              <section className="rounded-md border border-slate-800 bg-slate-900/40 p-6">
                <h2 className="mb-5 font-mono text-sm text-slate-300">Threat breakdown</h2>
                <ExplainabilityPanel threat={report.threat} auth={report.auth} />
              </section>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
