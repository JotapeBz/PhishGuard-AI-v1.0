// frontend/src/App.jsx
import { useState } from "react";
import axios from "axios";

const API = "http://localhost:8000";

const getRiskColor = (level) => ({
  LOW: "#22c55e", MEDIUM: "#f59e0b",
  HIGH: "#ef4444", CRITICAL: "#7c3aed"
}[level] || "#6b7280");

const getRiskBg = (level) => ({
  LOW: "#f0fdf4", MEDIUM: "#fffbeb",
  HIGH: "#fef2f2", CRITICAL: "#f5f3ff"
}[level] || "#f9fafb");

export default function App() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);

  const analyze = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const { data } = await axios.post(`${API}/analyze`, {
        url: url.trim(),
        check_ssl: true
      });
      setResult(data);
      setHistory(prev => [data, ...prev].slice(0, 10));
    } catch (e) {
      setError(e.response?.data?.detail || "Error al analizar la URL");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", background: "#0f172a", minHeight: "100vh", color: "#e2e8f0" }}>

      {/* Header */}
      <div style={{ background: "#1e293b", borderBottom: "1px solid #334155", padding: "16px 32px", display: "flex", alignItems: "center", gap: 12 }}>
        <span style={{ fontSize: 28 }}>🛡️</span>
        <div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700, color: "#f1f5f9" }}>PhishGuard AI</h1>
          <p style={{ margin: 0, fontSize: 12, color: "#64748b" }}>Detección de phishing en tiempo real · ML + SSL + NLP</p>
        </div>
      </div>

      <div style={{ maxWidth: 900, margin: "0 auto", padding: "32px 24px" }}>

        {/* Input */}
        <div style={{ background: "#1e293b", borderRadius: 16, padding: 28, marginBottom: 28, border: "1px solid #334155" }}>
          <p style={{ margin: "0 0 14px", fontSize: 14, color: "#94a3b8" }}>Ingresa una URL para analizar</p>
          <div style={{ display: "flex", gap: 10 }}>
            <input
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === "Enter" && analyze()}
              placeholder="https://ejemplo.com o URL sospechosa..."
              style={{
                flex: 1, padding: "12px 16px", borderRadius: 10, border: "1px solid #334155",
                background: "#0f172a", color: "#f1f5f9", fontSize: 15, outline: "none"
              }}
            />
            <button
              onClick={analyze}
              disabled={loading || !url.trim()}
              style={{
                padding: "12px 28px", borderRadius: 10, border: "none", cursor: "pointer",
                background: loading ? "#334155" : "#6366f1", color: "#fff",
                fontSize: 15, fontWeight: 600, transition: "all 0.2s"
              }}
            >
              {loading ? "Analizando..." : "Analizar →"}
            </button>
          </div>

          {/* URLs de ejemplo */}
          <div style={{ marginTop: 12, display: "flex", gap: 8, flexWrap: "wrap" }}>
            <span style={{ fontSize: 12, color: "#475569" }}>Probar:</span>
            {["https://google.com", "http://paypal-login.tk/verify", "http://192.168.1.1/admin"].map(u => (
              <button key={u} onClick={() => setUrl(u)} style={{
                fontSize: 11, padding: "3px 10px", borderRadius: 20, border: "1px solid #334155",
                background: "transparent", color: "#94a3b8", cursor: "pointer"
              }}>{u.slice(0, 35)}</button>
            ))}
          </div>
        </div>

        {error && (
          <div style={{ background: "#450a0a", border: "1px solid #7f1d1d", borderRadius: 12, padding: 16, marginBottom: 20, color: "#fca5a5" }}>
            ⚠️ {error}
          </div>
        )}

        {/* Resultado */}
        {result && (
          <div style={{ marginBottom: 28 }}>

            {/* Veredicto principal */}
            <div style={{
              background: getRiskBg(result.risk_level),
              border: `2px solid ${getRiskColor(result.risk_level)}`,
              borderRadius: 16, padding: 28, marginBottom: 20,
              display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 16
            }}>
              <div>
                <div style={{ fontSize: 13, color: "#64748b", marginBottom: 4 }}>Veredicto</div>
                <div style={{ fontSize: 28, fontWeight: 800, color: getRiskColor(result.risk_level) }}>{result.verdict}</div>
                <div style={{ fontSize: 13, color: "#475569", marginTop: 4 }}>{result.url.slice(0, 70)}</div>
              </div>
              <div style={{ textAlign: "right" }}>
                <div style={{ fontSize: 13, color: "#64748b" }}>Score de phishing</div>
                <div style={{ fontSize: 52, fontWeight: 800, color: getRiskColor(result.risk_level), lineHeight: 1 }}>
                  {Math.round(result.phishing_score * 100)}
                  <span style={{ fontSize: 20 }}>%</span>
                </div>
                <div style={{ fontSize: 12, color: "#64748b" }}>Confianza: {result.confidence} · {result.analysis_time_ms}ms</div>
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>

              {/* Factores de riesgo */}
              <div style={{ background: "#1e293b", borderRadius: 14, padding: 22, border: "1px solid #334155" }}>
                <h3 style={{ margin: "0 0 16px", fontSize: 15, color: "#f1f5f9" }}>⚡ Factores de Riesgo</h3>
                {result.top_risk_factors.length === 0
                  ? <p style={{ color: "#22c55e", fontSize: 14 }}>✓ Sin factores de riesgo detectados</p>
                  : result.top_risk_factors.map((f, i) => (
                    <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 0", borderBottom: "1px solid #1e293b" }}>
                      <span style={{ fontSize: 13, color: "#cbd5e1" }}>{f.factor}</span>
                      <span style={{
                        fontSize: 11, padding: "2px 8px", borderRadius: 20, fontWeight: 600,
                        background: { CRITICAL: "#3b0764", HIGH: "#450a0a", MEDIUM: "#431407", LOW: "#14532d" }[f.severity],
                        color: { CRITICAL: "#d8b4fe", HIGH: "#fca5a5", MEDIUM: "#fed7aa", LOW: "#86efac" }[f.severity]
                      }}>{f.severity}</span>
                    </div>
                  ))
                }
              </div>

              {/* SSL */}
              <div style={{ background: "#1e293b", borderRadius: 14, padding: 22, border: "1px solid #334155" }}>
                <h3 style={{ margin: "0 0 16px", fontSize: 15, color: "#f1f5f9" }}>🔐 Análisis SSL</h3>
                {result.ssl_result?.error
                  ? <p style={{ color: "#64748b", fontSize: 13 }}>No disponible para esta URL</p>
                  : result.ssl_result && Object.entries({
                    "HTTPS": result.ssl_result.has_ssl ? "✓ Sí" : "✗ No",
                    "Cert válido": result.ssl_result.cert_valid ? "✓ Sí" : "✗ No",
                    "Emisor": result.ssl_result.issuer?.slice(0, 22) || "—",
                    "Expira en": `${result.ssl_result.days_until_expiry} días`,
                    "Auto-firmado": result.ssl_result.is_self_signed ? "⚠ Sí" : "✓ No",
                    "Risk SSL": `${Math.round(result.ssl_result.risk_score * 100)}%`
                  }).map(([k, v]) => (
                    <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: "1px solid #0f172a" }}>
                      <span style={{ fontSize: 13, color: "#94a3b8" }}>{k}</span>
                      <span style={{ fontSize: 13, color: "#e2e8f0", fontWeight: 500 }}>{v}</span>
                    </div>
                  ))
                }
              </div>
            </div>

            {/* Features de URL */}
            <div style={{ background: "#1e293b", borderRadius: 14, padding: 22, border: "1px solid #334155", marginBottom: 16 }}>
              <h3 style={{ margin: "0 0 16px", fontSize: 15, color: "#f1f5f9" }}>🔍 Features Extraídas</h3>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10 }}>
                {Object.entries(result.url_features).map(([k, v]) => (
                  <div key={k} style={{ background: "#0f172a", borderRadius: 10, padding: "10px 12px", textAlign: "center" }}>
                    <div style={{ fontSize: 16, fontWeight: 700, color: "#6366f1" }}>
                      {typeof v === "boolean" ? (v ? "✓" : "✗") : v}
                    </div>
                    <div style={{ fontSize: 10, color: "#64748b", marginTop: 4 }}>{k.replace(/_/g, " ")}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Recomendación */}
            <div style={{
              background: "#1e293b", borderRadius: 14, padding: 18, border: "1px solid #334155",
              display: "flex", alignItems: "center", gap: 12
            }}>
              <span style={{ fontSize: 22 }}>💡</span>
              <div>
                <span style={{ fontSize: 13, color: "#94a3b8" }}>Recomendación: </span>
                <span style={{ fontSize: 13, fontWeight: 600, color: "#f1f5f9" }}>{result.recommendation}</span>
              </div>
            </div>
          </div>
        )}

        {/* Historial */}
        {history.length > 1 && (
          <div style={{ background: "#1e293b", borderRadius: 14, padding: 22, border: "1px solid #334155" }}>
            <h3 style={{ margin: "0 0 16px", fontSize: 15, color: "#f1f5f9" }}>📋 Historial de análisis</h3>
            {history.slice(1).map((h, i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 0", borderBottom: "1px solid #0f172a" }}>
                <span style={{ fontSize: 12, color: "#94a3b8", flex: 1 }}>{h.url.slice(0, 55)}...</span>
                <span style={{ fontSize: 12, fontWeight: 700, color: getRiskColor(h.risk_level), marginLeft: 12 }}>
                  {Math.round(h.phishing_score * 100)}% — {h.verdict}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}