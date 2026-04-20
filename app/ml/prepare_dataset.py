# app/ml/prepare_dataset.py
import pandas as pd
import numpy as np
import sys
import os
sys.path.insert(0, '.')

from app.analyzers.url_analyzer import URLAnalyzer

def load_phishing_urls(path: str, limit: int = 5000) -> list:
    urls = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            url = line.strip()
            if url and url.startswith('http'):
                urls.append(url)
            if len(urls) >= limit:
                break
    return urls

def load_legitimate_urls(path: str, limit: int = 5000) -> list:
    urls = []
    df = pd.read_csv(path, header=None, names=['rank', 'domain'])
    for domain in df['domain'].head(limit * 2):
        urls.append(f"https://www.{domain}")
        if len(urls) >= limit:
            break
    return urls

def build_dataset(phishing_path: str, legit_path: str, output_path: str):
    analyzer = URLAnalyzer()

    print("Cargando URLs de phishing...")
    phishing_urls = load_phishing_urls(phishing_path, limit=5000)
    print(f"  → {len(phishing_urls)} URLs de phishing cargadas")

    print("Cargando URLs legítimas...")
    legit_urls = load_legitimate_urls(legit_path, limit=5000)
    print(f"  → {len(legit_urls)} URLs legítimas cargadas")

    feature_names = [
        'url_length', 'domain_length', 'path_length', 'subdomain_length',
        'num_dots', 'num_hyphens', 'num_underscores', 'num_at_symbols',
        'num_question_marks', 'num_equals', 'num_slashes', 'num_percent',
        'num_digits_in_domain', 'has_ip_address', 'has_https',
        'num_subdomains', 'has_suspicious_tld', 'is_shortened_url',
        'has_port', 'has_brand_in_subdomain', 'has_brand_in_path',
        'entropy', 'digit_ratio', 'special_char_ratio', 'label'
    ]

    rows = []

    print("\nExtrayendo features de URLs phishing...")
    for i, url in enumerate(phishing_urls):
        if i % 500 == 0:
            print(f"  → {i}/{len(phishing_urls)}")
        try:
            features = analyzer.analyze(url)
            vector = analyzer.to_vector(features) + [1]  # label=1 phishing
            rows.append(vector)
        except Exception:
            continue

    print("Extrayendo features de URLs legítimas...")
    for i, url in enumerate(legit_urls):
        if i % 500 == 0:
            print(f"  → {i}/{len(legit_urls)}")
        try:
            features = analyzer.analyze(url)
            vector = analyzer.to_vector(features) + [0]  # label=0 legítima
            rows.append(vector)
        except Exception:
            continue

    df = pd.DataFrame(rows, columns=feature_names)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle
    df.to_csv(output_path, index=False)

    print(f"\n✓ Dataset guardado en {output_path}")
    print(f"  Total filas: {len(df)}")
    print(f"  Phishing:    {df['label'].sum()}")
    print(f"  Legítimas:   {(df['label'] == 0).sum()}")
    print(f"  Features:    {len(df.columns) - 1}")

if __name__ == "__main__":
    build_dataset(
        phishing_path="data/raw/phishing_urls.txt",
        legit_path="data/raw/top-1m.csv",
        output_path="data/processed/dataset.csv"
    )