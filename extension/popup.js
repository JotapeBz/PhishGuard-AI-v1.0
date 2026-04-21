const API = "https://phishguard-ai-v1-0.onrender.com";

const COLORS = {
  LOW:      { bg: "#f0fdf4", border: "#22c55e", text: "#15803d" },
  MEDIUM:   { bg: "#fffbeb", border: "#f59e0b", text: "#b45309" },
  HIGH:     { bg: "#fef2f2", border: "#ef4444", text: "#b91c1c" },
  CRITICAL: { bg: "#f5f3ff", border: "#7c3aed", text: "#6d28d9" }
};

const BADGE_STYLE = {
  CRITICAL: { bg: "#3b0764", color: "#d8b4fe" },
  HIGH:     { bg: "#450a0a", color: "#fca5a5" },
  MEDIUM:   { bg: "#431407", color: "#fed7aa" },
  LOW:      { bg: "#14532d", color: "#86efac" }
};

async function analyzeCurrentUrl() {
  const btn = document.getElementById("analyzeBtn");
  const loading = document.getElementById("loading");
  const resultDiv = document.getElementById("result");
  const errorDiv = document.getElementById("error");
  const checkSSL = document.getElementById("checkSSL").checked;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let url = tab.url;

  // Limpiar URL — quedarse solo con protocolo + dominio + path corto
  try {
    const parsed = new URL(url);
    url = parsed.origin + parsed.pathname;
  } catch(e) {}

  console.log("Analizando URL limpia:", url);

  if (!url || url.startsWith("chrome://")) {
    showError("No se puede analizar páginas internas de Chrome.");
    return;
  }

  btn.disabled = true;
  btn.textContent = "Conectando...";
  loading.style.display = "block";
  resultDiv.style.display = "none";
  errorDiv.style.display = "none";

  try {
    console.log("Enviando request a:", `${API}/analyze`);
    
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 35000); // 35s timeout para Render

    const res = await fetch(`${API}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, check_ssl: checkSSL }),
      signal: controller.signal
    });

    clearTimeout(timeout);
    console.log("Response status:", res.status);

    if (!res.ok) throw new Error(`Error HTTP ${res.status}`);
    
    const data = await res.json();
    console.log("Resultado:", data);
    renderResult(data);
    document.getElementById("timing").textContent = `${data.analysis_time_ms}ms`;

  } catch (e) {
    console.error("Error completo:", e);
    if (e.name === "AbortError") {
      showError("Timeout — el servidor tardó más de 35s.\nRender puede estar durmiendo.\nIntenta de nuevo en 30 segundos.");
    } else {
      showError(`Error: ${e.message}\n\nVerifica que ${API}/health responde en el navegador.`);
    }
  } finally {
    btn.disabled = false;
    btn.textContent = "Analizar esta URL";
    loading.style.display = "none";
  }
}

function renderResult(data) {
  const div = document.getElementById("result");
  const c = COLORS[data.risk_level] || COLORS.MEDIUM;
  const pct = Math.round(data.phishing_score * 100);

  const factorsHtml = data.top_risk_factors.length === 0
    ? `<div style="color:#22c55e;font-size:12px;margin-top:8px">✓ Sin factores de riesgo detectados</div>`
    : data.top_risk_factors.map(f => {
        const bs = BADGE_STYLE[f.severity] || BADGE_STYLE.LOW;
        return `
          <div class="factor-item">
            <span style="color:#cbd5e1">${f.factor}</span>
            <span class="badge" style="background:${bs.bg};color:${bs.color}">${f.severity}</span>
          </div>`;
      }).join("");

  div.style.cssText = `display:block;margin-top:14px;border-radius:12px;padding:16px;
    border:2px solid ${c.border};background:${c.bg}`;

  div.innerHTML = `
    <div class="score-row">
      <div>
        <div style="font-size:11px;color:#64748b;margin-bottom:3px">Veredicto</div>
        <div class="verdict" style="color:${c.text}">${data.verdict}</div>
      </div>
      <div style="text-align:right">
        <div style="font-size:11px;color:#64748b">Score</div>
        <div class="score" style="color:${c.text}">${pct}<span>%</span></div>
      </div>
    </div>
    <div class="factors">${factorsHtml}</div>
    <div class="meta">💡 ${data.recommendation}</div>
  `;
}

function showError(msg) {
  const div = document.getElementById("error");
  div.style.display = "block";
  div.style.whiteSpace = "pre-line";
  div.textContent = "⚠️ " + msg;
}

document.addEventListener("DOMContentLoaded", async () => {
  // Registrar el click del botón aquí
  document.getElementById("analyzeBtn").addEventListener("click", analyzeCurrentUrl);

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const urlBox = document.getElementById("currentUrl");
  if (tab?.url) {
    urlBox.textContent = tab.url.length > 60
      ? tab.url.slice(0, 60) + "..."
      : tab.url;
  }
});