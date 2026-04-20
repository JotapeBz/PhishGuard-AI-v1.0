# app/ml/train.py
import pandas as pd
import numpy as np
import joblib
import sys
import os
sys.path.insert(0, '.')

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, accuracy_score
)
from xgboost import XGBClassifier
import shap

FEATURE_NAMES = [
    'url_length', 'domain_length', 'path_length', 'subdomain_length',
    'num_dots', 'num_hyphens', 'num_underscores', 'num_at_symbols',
    'num_question_marks', 'num_equals', 'num_slashes', 'num_percent',
    'num_digits_in_domain', 'has_ip_address', 'has_https',
    'num_subdomains', 'has_suspicious_tld', 'is_shortened_url',
    'has_port', 'has_brand_in_subdomain', 'has_brand_in_path',
    'entropy', 'digit_ratio', 'special_char_ratio'
]

def train():
    print("="*55)
    print("PhishGuard AI — Entrenamiento del Modelo")
    print("="*55)

    # ── Cargar datos ────────────────────────────────────────────
    print("\nCargando dataset...")
    df = pd.read_csv("data/processed/dataset.csv")
    X = df[FEATURE_NAMES].values
    y = df['label'].values
    print(f"  → {len(df)} muestras cargadas")

    # ── Split train/test ────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  → Train: {len(X_train)} | Test: {len(X_test)}")

    # ── Modelos ─────────────────────────────────────────────────
    print("\nEntrenando Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        random_state=42,
        n_jobs=-1  # usa todos los cores del M1
    )
    rf.fit(X_train, y_train)

    print("Entrenando XGBoost...")
    xgb = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        random_state=42,
        eval_metric='logloss',
        verbosity=0
    )
    xgb.fit(X_train, y_train)

    # ── Ensemble: combinar ambos modelos ────────────────────────
    print("Creando Ensemble (RF + XGBoost)...")
    ensemble = VotingClassifier(
        estimators=[('rf', rf), ('xgb', xgb)],
        voting='soft'  # usa probabilidades, más preciso
    )
    ensemble.fit(X_train, y_train)

    # ── Evaluación ──────────────────────────────────────────────
    print("\n" + "="*55)
    print("RESULTADOS")
    print("="*55)

    y_pred = ensemble.predict(X_test)
    y_proba = ensemble.predict_proba(X_test)[:, 1]

    print(f"\nAccuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"ROC-AUC:   {roc_auc_score(y_test, y_proba):.4f}")
    print("\nReporte completo:")
    print(classification_report(y_test, y_pred,
          target_names=['Legítima', 'Phishing']))

    cm = confusion_matrix(y_test, y_pred)
    print("Matriz de confusión:")
    print(f"  Verdaderos negativos: {cm[0][0]}")
    print(f"  Falsos positivos:     {cm[0][1]}")
    print(f"  Falsos negativos:     {cm[1][0]}")
    print(f"  Verdaderos positivos: {cm[1][1]}")

    # ── Top features más importantes ────────────────────────────
    print("\nTop 10 features más importantes (Random Forest):")
    importances = rf.feature_importances_
    indices = np.argsort(importances)[::-1][:10]
    for i, idx in enumerate(indices):
        print(f"  {i+1:2}. {FEATURE_NAMES[idx]:<28} {importances[idx]:.4f}")

    # ── Guardar modelo ──────────────────────────────────────────
    os.makedirs("models", exist_ok=True)
    joblib.dump(ensemble, "models/phishguard_model.pkl")
    joblib.dump(FEATURE_NAMES, "models/feature_names.pkl")
    print("\n✓ Modelo guardado en models/phishguard_model.pkl")

    # ── Test rápido con URLs reales ─────────────────────────────
    print("\n" + "="*55)
    print("Test con URLs reales:")
    print("="*55)
    from app.analyzers.url_analyzer import URLAnalyzer
    analyzer = URLAnalyzer()

    test_urls = [
        ("https://www.google.com", "legítima"),
        ("http://paypal-secure-login.tk/verify?id=abc123", "phishing"),
        ("https://github.com/user/repo", "legítima"),
        ("http://192.168.1.1/bank/login.php", "phishing"),
        ("https://amazon.com/orders", "legítima"),
    ]

    for url, expected in test_urls:
        features = analyzer.analyze(url)
        vector = analyzer.to_vector(features)
        proba = ensemble.predict_proba([vector])[0][1]
        pred = "PHISHING" if proba > 0.5 else "LEGÍTIMA"
        match = "✓" if (pred == "PHISHING") == (expected == "phishing") else "✗"
        print(f"  {match} [{pred} {proba:.2f}] {url[:50]}")

    print("\n✓ Entrenamiento completado exitosamente\n")

if __name__ == "__main__":
    train()