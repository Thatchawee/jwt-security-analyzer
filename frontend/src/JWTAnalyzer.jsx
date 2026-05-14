import { useState, useCallback } from "react";
import "./App.css";

const API_BASE = "http://127.0.0.1:8000";

const SEVERITY_CONFIG = {
  CRITICAL: { color: "#ff4466", borderColor: "rgba(255,68,102,0.38)", bg: "rgba(255,68,102,0.08)", label: "CRITICAL", icon: "☠" },
  HIGH:     { color: "#ffaa00", borderColor: "rgba(255,170,0,0.38)",   bg: "rgba(255,170,0,0.08)",   label: "HIGH",     icon: "⚡" },
  MEDIUM:   { color: "#f5c542", borderColor: "rgba(245,197,66,0.38)",  bg: "rgba(245,197,66,0.08)",  label: "MEDIUM",   icon: "⚠" },
  LOW:      { color: "#00d4ff", borderColor: "rgba(0,212,255,0.38)",   bg: "rgba(0,212,255,0.08)",   label: "LOW",      icon: "ℹ" },
};

const SAMPLE_TOKEN = "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.";

const TABS = [
  { id: "decoded",         label: "DECODED",  icon: "◈" },
  { id: "vulnerabilities", label: "VULNS",    icon: "⚠" },
  { id: "attacks",         label: "ATTACKS",  icon: "⚔" },
  { id: "recommendations", label: "FIXES",    icon: "◉" },
];

export default function JWTAnalyzer() {
  const [token, setToken] = useState("");
  const [result, setResult] = useState(null);
  const [rsaKeys, setRsaKeys] = useState(null);
  const [loading, setLoading] = useState(false);
  const [rsaLoading, setRsaLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState("decoded");
  const [copied, setCopied] = useState(null);
  const [rsaView, setRsaView] = useState("public");

  const [algToken, setAlgToken] = useState("");
  const [algPublicKey, setAlgPublicKey] = useState("");
  const [algResult, setAlgResult] = useState(null);
  const [algLoading, setAlgLoading] = useState(false);

  const copy = useCallback((text, key) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(key);
      setTimeout(() => setCopied(null), 2000);
    });
  }, []);

  async function analyzeToken() {
    if (!token.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    setRsaKeys(null);
    try {
      const res = await fetch(`${API_BASE}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: token.trim() }),
      });
      const data = await res.json();
      if (data.status === "success") {
        setResult(data);
        setActiveTab("decoded");
      } else {
        setError("Analysis failed. Check your token format.");
      }
    } catch {
      setError("Cannot connect to backend. Make sure it's running on port 8000.");
    } finally {
      setLoading(false);
    }
  }

  async function generateRSA() {
    setRsaLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/generate-rsa`);
      const data = await res.json();
      if (data.status === "success") {
        setRsaKeys(data.keys);
        setRsaView("public");
      } else {
        setError("RSA generation failed.");
      }
    } catch {
      setError("Cannot connect to backend.");
    } finally {
      setRsaLoading(false);
    }
  }

  async function runAlgConfusion() {
    if (!algToken.trim() || !algPublicKey.trim()) return;
    setAlgLoading(true);
    setError(null);
    setAlgResult(null);
    try {
      const res = await fetch(`${API_BASE}/attack/alg-confusion`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: algToken.trim(), public_key_pem: algPublicKey.trim() }),
      });
      const data = await res.json();
      setAlgResult(data);
    } catch {
      setError("Cannot connect to backend. Make sure it's running on port 8000.");
    } finally {
      setAlgLoading(false);
    }
  }

  const vulns      = result?.analysis?.vulnerabilities || [];
  const recs       = result?.analysis?.recommendations || [];
  const dictAttack = result?.analysis?.active_attacks?.dictionary_attack;
  const critCount  = vulns.filter((v) => v.severity === "CRITICAL").length + (dictAttack?.cracked ? 1 : 0);
  const highCount  = vulns.filter((v) => v.severity === "HIGH").length;
  const isVuln     = critCount > 0 || highCount > 0;

  const tabBadges = {
    vulnerabilities: vulns.length || null,
    attacks:         dictAttack ? 1 : null,
    recommendations: recs.length || null,
  };

  const isValidJwt = token.trim().split(".").length === 3;

  return (
    <div className="jwt-root">
      <div className="scan-line" />

      {/* ── Header ── */}
      <header className="jwt-header">
        <div style={{ maxWidth: 980, margin: "0 auto", display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0.9rem 0" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "1.1rem" }}>
            {/* Logo icon with double-ring glow */}
            <div style={{ position: "relative", flexShrink: 0 }}>
              <div style={{
                width: 46, height: 46,
                border: "1px solid rgba(0,255,136,0.32)",
                borderRadius: 10,
                display: "flex", alignItems: "center", justifyContent: "center",
                background: "linear-gradient(135deg, rgba(0,255,136,0.07), rgba(0,255,136,0.02))",
                fontSize: "1.35rem",
                boxShadow: "0 0 18px rgba(0,255,136,0.12), inset 0 0 12px rgba(0,255,136,0.04)",
              }}>
                🔐
              </div>
              {/* corner accent */}
              <div style={{
                position: "absolute", bottom: -2, right: -2,
                width: 10, height: 10,
                borderRight: "2px solid rgba(0,255,136,0.5)",
                borderBottom: "2px solid rgba(0,255,136,0.5)",
                borderRadius: "0 0 3px 0",
              }} />
            </div>
            <div>
              <h1 style={{ margin: 0, fontSize: "1.3rem", fontWeight: 700, letterSpacing: "0.07em", color: "#e2e8f0", fontFamily: "var(--font)", lineHeight: 1 }}>
                JWT<span style={{ color: "var(--accent)", textShadow: "0 0 12px rgba(0,255,136,0.4)" }}>SEC</span>
              </h1>
              <p style={{ margin: "0.2rem 0 0", fontSize: "0.55rem", color: "rgba(0,255,136,0.28)", letterSpacing: "0.3em", textTransform: "uppercase" }}>
                Security Analyzer
              </p>
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "1.5rem" }}>
            {/* Version badge */}
            <span style={{
              fontSize: "0.55rem", color: "rgba(0,212,255,0.4)",
              border: "1px solid rgba(0,212,255,0.18)",
              padding: "0.18rem 0.55rem", borderRadius: 4, letterSpacing: "0.12em",
              background: "rgba(0,212,255,0.04)",
            }}>
              v2.0
            </span>
            <div style={{ display: "flex", alignItems: "center", gap: "0.55rem" }}>
              <div className="status-dot" />
              <span style={{ fontSize: "0.58rem", color: "var(--accent)", letterSpacing: "0.2em" }}>ONLINE</span>
            </div>
          </div>
        </div>
      </header>

      <main style={{ maxWidth: 980, margin: "0 auto", padding: "2rem", display: "flex", flexDirection: "column", gap: "1.25rem", position: "relative", zIndex: 1 }}>

        {/* ── Token Input ── */}
        <section className="panel">
          <div className="panel-header">
            <span className="panel-label">◈ TOKEN INPUT</span>
            <div style={{ display: "flex", gap: "0.55rem", alignItems: "center" }}>
              <button
                className={`sample-btn${!token ? " sample-btn-pulse" : ""}`}
                onClick={() => setToken(SAMPLE_TOKEN)}
              >
                ▶ LOAD SAMPLE
              </button>
              {token && (
                <button className="copy-btn" onClick={() => copy(token, "token-input")}>
                  {copied === "token-input" ? "✓ COPIED" : "COPY"}
                </button>
              )}
            </div>
          </div>
          <textarea
            className="token-input"
            placeholder="Paste your JWT token here  (eyJ...)"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            spellCheck={false}
          />
          {!token && (
            <div className="token-hint">
              <span>▶</span>
              No token? Click <strong style={{ color: "rgba(0,212,255,0.6)", margin: "0 0.3em" }}>LOAD SAMPLE</strong> to try with a vulnerable JWT
            </div>
          )}
          <div style={{ display: "flex", gap: "0.75rem", padding: "0.8rem 1.3rem", borderTop: "1px solid var(--border)", flexWrap: "wrap", alignItems: "center" }}>
            <button
              className={`btn btn-primary${loading ? " loading-shimmer" : ""}`}
              onClick={analyzeToken}
              disabled={loading || !token.trim()}
            >
              {loading ? "⟳  ANALYZING..." : "⚡  ANALYZE TOKEN"}
            </button>
            <button className="btn btn-secondary" onClick={generateRSA} disabled={rsaLoading}>
              {rsaLoading ? "⟳  GENERATING..." : "◈  GENERATE RSA KEYS"}
            </button>
            {token && (
              <span style={{ marginLeft: "auto", fontSize: "0.58rem", letterSpacing: "0.1em", color: isValidJwt ? "var(--accent)" : "var(--danger)", opacity: 0.8 }}>
                {isValidJwt ? "✓  JWT FORMAT" : "⚠  INVALID FORMAT"}
              </span>
            )}
          </div>
        </section>

        {/* ── Error ── */}
        {error && (
          <div className="error-box">
            <span style={{ color: "var(--danger)", fontSize: "1rem", flexShrink: 0 }}>⚠</span>
            {error}
          </div>
        )}

        {/* ── Results ── */}
        {result && (
          <>
            {/* Summary row */}
            <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
              <div className="summary-card" style={{ borderColor: critCount > 0 ? "rgba(255,68,102,0.25)" : "var(--border)" }}>
                <span className={critCount > 0 ? "crit-glow" : ""} style={{ fontSize: "2.2rem", fontWeight: 700, color: "#ff4466", lineHeight: 1 }}>
                  {critCount}
                </span>
                <span style={{ fontSize: "0.57rem", color: critCount > 0 ? "rgba(255,68,102,0.6)" : "var(--text-muted)", letterSpacing: "0.15em" }}>CRITICAL</span>
              </div>
              <div className="summary-card" style={{ borderColor: highCount > 0 ? "rgba(255,170,0,0.22)" : "var(--border)" }}>
                <span style={{ fontSize: "2.2rem", fontWeight: 700, color: "#ffaa00", lineHeight: 1, textShadow: highCount > 0 ? "0 0 14px rgba(255,170,0,0.4)" : "none" }}>
                  {highCount}
                </span>
                <span style={{ fontSize: "0.57rem", color: highCount > 0 ? "rgba(255,170,0,0.6)" : "var(--text-muted)", letterSpacing: "0.15em" }}>HIGH</span>
              </div>
              <div className="summary-card">
                <span style={{ fontSize: "2.2rem", fontWeight: 700, color: "var(--accent)", lineHeight: 1 }}>{vulns.length}</span>
                <span style={{ fontSize: "0.57rem", color: "var(--text-muted)", letterSpacing: "0.15em" }}>TOTAL ISSUES</span>
              </div>
              <div className="summary-card" style={{ flex: 2, borderColor: isVuln ? "rgba(255,68,102,0.22)" : "rgba(0,255,136,0.18)" }}>
                <span style={{
                  fontSize: "0.92rem", fontWeight: 700, letterSpacing: "0.1em", lineHeight: 1,
                  color: isVuln ? "#ff4466" : "var(--accent)",
                  textShadow: isVuln ? "0 0 14px rgba(255,68,102,0.45)" : "0 0 10px rgba(0,255,136,0.35)",
                }}>
                  {isVuln ? "⚠  VULNERABLE" : "✓  LOOKS SAFE"}
                </span>
                <span style={{ fontSize: "0.57rem", color: "var(--text-muted)", letterSpacing: "0.15em" }}>VERDICT</span>
                <div style={{ marginTop: "0.55rem", height: 3, borderRadius: 2, background: "rgba(255,255,255,0.05)", overflow: "hidden" }}>
                  <div style={{
                    height: "100%",
                    width: isVuln ? `${Math.min(100, critCount * 40 + highCount * 20)}%` : "100%",
                    background: isVuln
                      ? "linear-gradient(90deg, #ff4466, #ff8866)"
                      : "linear-gradient(90deg, #00ff88, #00dd77)",
                    borderRadius: 2,
                    transition: "width 0.7s ease",
                    boxShadow: isVuln ? "0 0 6px rgba(255,68,102,0.5)" : "0 0 6px rgba(0,255,136,0.4)",
                  }} />
                </div>
              </div>
            </div>

            {/* Tabs */}
            <div className="tabs">
              {TABS.map(({ id, label, icon }) => (
                <button
                  key={id}
                  className={`tab-btn${activeTab === id ? " active" : ""}`}
                  onClick={() => setActiveTab(id)}
                >
                  <span style={{ opacity: 0.65 }}>{icon}</span>
                  {label}
                  {tabBadges[id] != null && (
                    <span style={{
                      background: activeTab === id ? "rgba(0,255,136,0.15)" : "rgba(255,255,255,0.05)",
                      color: activeTab === id ? "var(--accent)" : "var(--text-muted)",
                      padding: "0.05rem 0.38rem",
                      borderRadius: 10,
                      fontSize: "0.56rem",
                      fontWeight: 700,
                    }}>
                      {tabBadges[id]}
                    </span>
                  )}
                </button>
              ))}
            </div>

            {/* Tab: Decoded */}
            {activeTab === "decoded" && (
              <div className="panel">
                <div className="panel-header">
                  <span className="panel-label">◈ DECODED TOKEN PARTS</span>
                  <span style={{ fontSize: "0.58rem", color: "var(--text-muted)", letterSpacing: "0.1em" }}>
                    alg: <span style={{ color: "var(--accent)" }}>{result.decoded?.header?.alg ?? "—"}</span>
                    {" · "}typ: <span style={{ color: "var(--accent)" }}>{result.decoded?.header?.typ ?? "—"}</span>
                  </span>
                </div>

                <div className="decoded-grid">
                  {["header", "payload"].map((part) => (
                    <div key={part} style={{ padding: "1.1rem 1.25rem" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.6rem" }}>
                        <span style={{ fontSize: "0.57rem", color: "var(--text-muted)", letterSpacing: "0.22em", textTransform: "uppercase" }}>{part}</span>
                        <button className="copy-btn" onClick={() => copy(JSON.stringify(result.decoded[part], null, 2), part)}>
                          {copied === part ? "✓ COPIED" : "COPY"}
                        </button>
                      </div>
                      <pre className="code-block">{JSON.stringify(result.decoded[part], null, 2)}</pre>
                    </div>
                  ))}
                </div>

                <div style={{ padding: "1.1rem 1.25rem", borderTop: "1px solid var(--border)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.6rem" }}>
                    <span style={{ fontSize: "0.57rem", color: "var(--text-muted)", letterSpacing: "0.22em" }}>SIGNATURE</span>
                    {result.decoded.signature && (
                      <button className="copy-btn" onClick={() => copy(result.decoded.signature, "sig")}>
                        {copied === "sig" ? "✓ COPIED" : "COPY"}
                      </button>
                    )}
                  </div>
                  <pre className="code-block" style={{ color: result.decoded.signature ? "var(--accent)" : "var(--danger)" }}>
                    {result.decoded.signature || '"" — EMPTY SIGNATURE  (alg:none attack!)'}
                  </pre>
                </div>
              </div>
            )}

            {/* Tab: Vulnerabilities */}
            {activeTab === "vulnerabilities" && (
              <div className="panel">
                <div className="panel-header">
                  <span className="panel-label">⚠ VULNERABILITIES</span>
                  <span style={{ fontSize: "0.58rem", color: "var(--text-muted)" }}>{vulns.length} issue(s) found</span>
                </div>
                {vulns.length === 0 ? (
                  <div style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)", fontSize: "0.8rem" }}>
                    <div style={{ fontSize: "2.2rem", marginBottom: "0.6rem" }}>✓</div>
                    No vulnerabilities detected
                  </div>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem", padding: "1.25rem" }}>
                    {vulns.map((v, i) => {
                      const cfg = SEVERITY_CONFIG[v.severity] || SEVERITY_CONFIG.LOW;
                      return (
                        <div key={i} className="vuln-card" style={{ borderColor: cfg.borderColor, background: cfg.bg }}>
                          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.5rem" }}>
                            <span style={{
                              fontSize: "0.57rem", fontWeight: 700, letterSpacing: "0.15em",
                              border: "1px solid", padding: "0.15rem 0.55rem", borderRadius: 3,
                              fontFamily: "var(--font)", color: cfg.color, borderColor: cfg.borderColor, background: cfg.bg,
                            }}>
                              {cfg.icon} {cfg.label}
                            </span>
                            <span style={{ fontSize: "0.82rem", fontWeight: 700, color: "#d0dce8" }}>{v.type}</span>
                          </div>
                          <p style={{ margin: 0, fontSize: "0.75rem", color: "rgba(200,215,228,0.68)", lineHeight: 1.75 }}>{v.description}</p>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* Tab: Attacks */}
            {activeTab === "attacks" && (
              <div className="panel">
                <div className="panel-header">
                  <span className="panel-label">⚔ ACTIVE ATTACK RESULTS</span>
                </div>
                <div style={{ padding: "1.25rem" }}>
                  <div style={{ fontSize: "0.57rem", color: "var(--text-muted)", letterSpacing: "0.2em", marginBottom: "0.75rem" }}>
                    DICTIONARY ATTACK — HS256 SECRET CRACKER
                  </div>
                  {dictAttack ? (
                    <div className="vuln-card" style={{
                      borderColor: dictAttack.cracked ? "rgba(255,68,102,0.4)" : "rgba(0,255,136,0.3)",
                      background:  dictAttack.cracked ? "rgba(255,68,102,0.08)" : "rgba(0,255,136,0.05)",
                    }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.5rem", flexWrap: "wrap" }}>
                        <span style={{
                          fontSize: "0.57rem", fontWeight: 700, letterSpacing: "0.15em",
                          border: "1px solid", padding: "0.15rem 0.55rem", borderRadius: 3,
                          fontFamily: "var(--font)",
                          color:       dictAttack.cracked ? "#ff4466" : "var(--accent)",
                          borderColor: dictAttack.cracked ? "rgba(255,68,102,0.4)" : "rgba(0,255,136,0.4)",
                          background:  dictAttack.cracked ? "rgba(255,68,102,0.1)" : "rgba(0,255,136,0.1)",
                        }}>
                          {dictAttack.cracked ? "☠  CRACKED" : "✓  SECURE"}
                        </span>
                        {dictAttack.cracked && (
                          <span style={{ fontSize: "0.78rem", color: "#ff4466", fontWeight: 700 }}>
                            Secret found:{" "}
                            <code style={{ background: "rgba(255,68,102,0.14)", padding: "0.1rem 0.5rem", borderRadius: 3, fontSize: "0.78rem" }}>
                              "{dictAttack.secret}"
                            </code>
                          </span>
                        )}
                      </div>
                      <p style={{ margin: 0, fontSize: "0.75rem", color: "rgba(200,215,228,0.68)", lineHeight: 1.75 }}>{dictAttack.message}</p>
                    </div>
                  ) : (
                    <div style={{ padding: "2rem", textAlign: "center", color: "var(--text-muted)", fontSize: "0.78rem" }}>
                      No dictionary attack data returned.
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Tab: Recommendations */}
            {activeTab === "recommendations" && (
              <div className="panel">
                <div className="panel-header">
                  <span className="panel-label">◉ FIX RECOMMENDATIONS</span>
                  <span style={{ fontSize: "0.58rem", color: "var(--text-muted)" }}>{recs.length} recommendation(s)</span>
                </div>
                {recs.length === 0 ? (
                  <div style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)", fontSize: "0.8rem" }}>
                    <div style={{ fontSize: "2.2rem", marginBottom: "0.6rem" }}>✓</div>
                    No recommendations.
                  </div>
                ) : (
                  <ol style={{ listStyle: "none", margin: 0, padding: "0.5rem 1.25rem" }}>
                    {recs.map((r, i) => (
                      <li key={i} className="rec-item">
                        <span style={{ color: "var(--accent)", fontWeight: 700, flexShrink: 0, fontSize: "0.67rem", fontFamily: "var(--font)", minWidth: "2rem" }}>
                          {String(i + 1).padStart(2, "0")}
                        </span>
                        <span>{r}</span>
                      </li>
                    ))}
                  </ol>
                )}
              </div>
            )}
          </>
        )}

        {/* ── RSA Keys Panel ── */}
        {rsaKeys && (
          <section className="panel">
            <div className="panel-header">
              <span className="panel-label">◈ GENERATED RSA KEYS</span>
              <span style={{ color: "var(--accent)", fontSize: "0.58rem", letterSpacing: "0.1em" }}>✓ Custom Implementation</span>
            </div>
            <div className="tabs">
              {["public", "private"].map((k) => (
                <button key={k} className={`tab-btn${rsaView === k ? " active" : ""}`} onClick={() => setRsaView(k)}>
                  {k === "public" ? "◈  PUBLIC KEY" : "◉  PRIVATE KEY"}
                </button>
              ))}
            </div>
            <div style={{ padding: "1.25rem" }}>
              <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: "0.6rem" }}>
                <button className="copy-btn" onClick={() => copy(JSON.stringify(rsaKeys[`${rsaView}_key`], null, 2), `rsa-${rsaView}`)}>
                  {copied === `rsa-${rsaView}` ? "✓ COPIED" : "COPY KEY"}
                </button>
              </div>
              <pre className="code-block" style={{ color: rsaView === "private" ? "#ffaa00" : "var(--accent)" }}>
                {JSON.stringify(rsaKeys[`${rsaView}_key`], null, 2)}
              </pre>
            </div>
          </section>
        )}

        {/* ── Algorithm Confusion Attack ── */}
        <section className="panel">
          <div className="panel-header">
            <span className="panel-label">⚔ ALGORITHM CONFUSION ATTACK</span>
            <span style={{ fontSize: "0.58rem", color: "var(--text-muted)", letterSpacing: "0.1em" }}>RS256 → HS256</span>
          </div>
          <div style={{ padding: "1.25rem", display: "flex", flexDirection: "column", gap: "1rem" }}>
            <div>
              <div style={{ fontSize: "0.57rem", color: "var(--text-muted)", letterSpacing: "0.2em", marginBottom: "0.5rem" }}>RS256 JWT TOKEN</div>
              <textarea
                className="token-input"
                style={{ border: "1px solid var(--border)", borderRadius: 6, minHeight: 75 }}
                placeholder="Paste RS256 JWT token here..."
                value={algToken}
                onChange={(e) => setAlgToken(e.target.value)}
                spellCheck={false}
              />
            </div>
            <div>
              <div style={{ fontSize: "0.57rem", color: "var(--text-muted)", letterSpacing: "0.2em", marginBottom: "0.5rem" }}>PUBLIC KEY — PEM FORMAT</div>
              <textarea
                className="token-input"
                style={{ border: "1px solid var(--border)", borderRadius: 6, minHeight: 100, color: "var(--cyan)" }}
                placeholder={"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}
                value={algPublicKey}
                onChange={(e) => setAlgPublicKey(e.target.value)}
                spellCheck={false}
              />
            </div>
            <div>
              <button
                className="btn btn-danger"
                onClick={runAlgConfusion}
                disabled={algLoading || !algToken.trim() || !algPublicKey.trim()}
              >
                {algLoading ? "⟳  ATTACKING..." : "⚔  RUN CONFUSION ATTACK"}
              </button>
            </div>

            {algResult && (
              <div className="vuln-card" style={{
                borderColor: algResult.success ? "rgba(255,68,102,0.4)" : "rgba(0,255,136,0.3)",
                background:  algResult.success ? "rgba(255,68,102,0.08)" : "rgba(0,255,136,0.05)",
                animation: "fadeIn 0.4s ease",
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.5rem" }}>
                  <span style={{
                    fontSize: "0.57rem", fontWeight: 700, letterSpacing: "0.15em",
                    border: "1px solid", padding: "0.15rem 0.55rem", borderRadius: 3, fontFamily: "var(--font)",
                    color:       algResult.success ? "#ff4466" : "var(--accent)",
                    borderColor: algResult.success ? "rgba(255,68,102,0.4)" : "rgba(0,255,136,0.4)",
                    background:  algResult.success ? "rgba(255,68,102,0.1)" : "rgba(0,255,136,0.1)",
                  }}>
                    {algResult.success ? "☠  VULNERABLE" : "✓  NOT VULNERABLE"}
                  </span>
                </div>
                <p style={{ margin: "0 0 0.75rem", fontSize: "0.75rem", color: "rgba(200,215,228,0.68)", lineHeight: 1.75 }}>{algResult.description}</p>
                {algResult.forged_token && (
                  <div>
                    <div style={{ fontSize: "0.57rem", color: "var(--text-muted)", letterSpacing: "0.2em", marginBottom: "0.5rem" }}>FORGED TOKEN</div>
                    <div style={{ position: "relative" }}>
                      <pre className="code-block" style={{ color: "var(--danger)", fontSize: "0.68rem" }}>
                        {algResult.forged_token}
                      </pre>
                      <button
                        className="copy-btn"
                        style={{ position: "absolute", top: "0.6rem", right: "0.6rem" }}
                        onClick={() => copy(algResult.forged_token, "forged")}
                      >
                        {copied === "forged" ? "✓ COPIED" : "COPY"}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </section>
      </main>

      <footer className="jwt-footer">
        JWTSEC · Network &amp; Computer Security Mini Project · SIIT · 2025
      </footer>
    </div>
  );
}
