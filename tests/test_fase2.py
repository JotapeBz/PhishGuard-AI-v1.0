import sys
sys.path.insert(0, '.')
import joblib
from app.analyzers.url_analyzer import URLAnalyzer
from app.analyzers.ssl_analyzer import SSLAnalyzer

print("\n" + "="*55)
print("PhishGuard AI — Verificación Fase 2")
print("="*55)

# Test modelo
print("\n[1] Cargando modelo entrenado...")
model = joblib.load("models/phishguard_model.pkl")
analyzer = URLAnalyzer()
url = "http://paypal-update-account.tk/login?redirect=verify"
features = analyzer.analyze(url)
proba = model.predict_proba([analyzer.to_vector(features)])[0][1]
print(f"  URL de prueba: {url[:50]}")
print(f"  Score phishing: {proba:.4f} → {'PHISHING ⚠' if proba > 0.5 else 'LEGÍTIMA ✓'}")

# Test SSL
print("\n[2] Analizando SSL de google.com...")
ssl_analyzer = SSLAnalyzer()
result = ssl_analyzer.analyze("https://www.google.com")
print(f"  Válido:        {result.cert_valid}")
print(f"  Emisor:        {result.issuer}")
print(f"  Días hasta exp: {result.days_until_expiry}")
print(f"  Risk score:    {result.risk_score}")
print(f"  Warnings:      {result.warnings or 'Ninguno'}")

print("\n✓ Fase 2 completada exitosamente\n")
