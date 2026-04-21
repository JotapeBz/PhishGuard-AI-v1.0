# app/main.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl
from typing import Optional
import joblib
import time
import os
import sys
sys.path.insert(0, '.')

from app.analyzers.url_analyzer import URLAnalyzer
from app.analyzers.ssl_analyzer import SSLAnalyzer

# ── Inicializar app ──────────────────────────────────────────
app = FastAPI(
    title="PhishGuard AI",
    description="Motor de detección de phishing en tiempo real",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Cargar modelo al arrancar ────────────────────────────────
MODEL_PATH = "models/phishguard_model.pkl"
model = None
url_analyzer = URLAnalyzer()
ssl_analyzer = SSLAnalyzer()

@app.on_event("startup")
async def load_model():
    global model
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print("✓ Modelo cargado correctamente")
    else:
        print("✗ Modelo no encontrado — entrena primero con train.py")

# ── Schemas ──────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    url: str
    check_ssl: bool = True

class FeatureDetail(BaseModel):
    name: str
    value: float
    risk_contribution: str

class AnalyzeResponse(BaseModel):
    url: str
    phishing_score: float
    verdict: str
    confidence: str
    risk_level: str
    analysis_time_ms: float
    url_features: dict
    ssl_result: Optional[dict]
    top_risk_factors: list
    recommendation: str

# ── Endpoints ────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "name": "PhishGuard AI",
        "status": "running",
        "model_loaded": model is not None,
        "endpoints": ["/analyze", "/health", "/docs"]
    }

@app.get("/health")
async def health():
    # Railway necesita 200 siempre, incluso si el modelo aún carga
    return {"status": "ok", "model_loaded": model is not None}

@app.get("/")
async def root():
    return {
        "name": "PhishGuard AI",
        "status": "running",
        "model_loaded": model is not None,
        "endpoints": ["/analyze", "/health", "/docs"]
    }

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_url(request: AnalyzeRequest):
    if model is None:
        raise HTTPException(503, "Modelo no disponible")

    start = time.time()
    url = request.url.strip()

    # Normalizar URL
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # ── Análisis de URL ──────────────────────────────────────
    features = url_analyzer.analyze(url)
    vector = url_analyzer.to_vector(features)
    phishing_proba = float(model.predict_proba([vector])[0][1])

    # ── Análisis SSL (opcional, puede tardar) ────────────────
    ssl_data = None
    if request.check_ssl:
        try:
            ssl_result = ssl_analyzer.analyze(url)
            ssl_data = {
                "has_ssl": ssl_result.has_ssl,
                "cert_valid": ssl_result.cert_valid,
                "issuer": ssl_result.issuer,
                "days_until_expiry": ssl_result.days_until_expiry,
                "is_self_signed": ssl_result.is_self_signed,
                "domain_matches": ssl_result.domain_matches,
                "cert_age_days": ssl_result.cert_age_days,
                "risk_score": ssl_result.risk_score,
                "warnings": ssl_result.warnings
            }
            # Ajustar score combinando ML + SSL
            ssl_weight = 0.2
            phishing_proba = min(
                phishing_proba * (1 - ssl_weight) +
                ssl_result.risk_score * ssl_weight,
                1.0
            )
        except Exception:
            ssl_data = {"error": "No se pudo analizar SSL"}

    # ── Calcular nivel de riesgo ─────────────────────────────
    risk_level, verdict, confidence, recommendation = _classify_risk(phishing_proba)

    # ── Top factores de riesgo ───────────────────────────────
    top_risk_factors = _get_risk_factors(features)

    elapsed = round((time.time() - start) * 1000, 2)

    return AnalyzeResponse(
        url=url,
        phishing_score=round(phishing_proba, 4),
        verdict=verdict,
        confidence=confidence,
        risk_level=risk_level,
        analysis_time_ms=elapsed,
        url_features={
            "url_length": features.url_length,
            "has_https": features.has_https,
            "has_ip_address": features.has_ip_address,
            "num_subdomains": features.num_subdomains,
            "has_suspicious_tld": features.has_suspicious_tld,
            "has_brand_in_subdomain": features.has_brand_in_subdomain,
            "entropy": features.entropy,
            "is_shortened_url": features.is_shortened_url,
            "num_dots": features.num_dots,
            "special_char_ratio": round(features.special_char_ratio, 4)
        },
        ssl_result=ssl_data,
        top_risk_factors=top_risk_factors,
        recommendation=recommendation
    )

def _classify_risk(score: float):
    if score < 0.25:
        return "LOW", "LEGÍTIMA", "Alta", "URL segura para visitar"
    elif score < 0.50:
        return "MEDIUM", "SOSPECHOSA", "Media", "Proceder con precaución"
    elif score < 0.75:
        return "HIGH", "PHISHING PROBABLE", "Alta", "Evitar esta URL"
    else:
        return "CRITICAL", "PHISHING CONFIRMADO", "Muy Alta", "No visitar bajo ninguna circunstancia"

def _get_risk_factors(features) -> list:
    factors = []
    if features.has_ip_address:
        factors.append({"factor": "IP en lugar de dominio", "severity": "CRITICAL"})
    if features.has_brand_in_subdomain:
        factors.append({"factor": "Marca conocida en subdominio", "severity": "HIGH"})
    if features.has_suspicious_tld:
        factors.append({"factor": "TLD sospechoso (.tk, .ml, etc)", "severity": "HIGH"})
    if not features.has_https:
        factors.append({"factor": "Sin HTTPS", "severity": "HIGH"})
    if features.entropy > 3.8:
        factors.append({"factor": f"Alta entropía en dominio ({features.entropy})", "severity": "MEDIUM"})
    if features.is_shortened_url:
        factors.append({"factor": "URL acortada", "severity": "MEDIUM"})
    if features.num_subdomains > 3:
        factors.append({"factor": f"Demasiados subdominios ({features.num_subdomains})", "severity": "MEDIUM"})
    if features.url_length > 100:
        factors.append({"factor": f"URL muy larga ({features.url_length} chars)", "severity": "LOW"})
    if features.num_at_symbols > 0:
        factors.append({"factor": "Símbolo @ en URL", "severity": "HIGH"})
    return factors[:5]  # Top 5 factores