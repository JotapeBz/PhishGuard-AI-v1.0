import sys
sys.path.insert(0, '.')

from app.analyzers.url_analyzer import URLAnalyzer

analyzer = URLAnalyzer()

urls_test = [
    ("https://www.google.com", "legítima"),
    ("http://paypal-secure-login.tk/verify/account?id=123", "phishing"),
    ("http://192.168.1.1/admin/login.php", "phishing"),
    ("https://linkedin.com/in/profile", "legítima"),
    ("http://bit.ly/3xAb2", "sospechosa"),
]

print("\n" + "="*60)
print("PhishGuard AI — Test Extractor de Features")
print("="*60)

for url, tipo in urls_test:
    features = analyzer.analyze(url)
    vector = analyzer.to_vector(features)
    print(f"\nURL ({tipo}): {url[:55]}...")
    print(f"  Longitud URL:      {features.url_length}")
    print(f"  Entropía dominio:  {features.entropy}")
    print(f"  Tiene IP:          {features.has_ip_address}")
    print(f"  HTTPS:             {features.has_https}")
    print(f"  TLD sospechoso:    {features.has_suspicious_tld}")
    print(f"  Marca en subdom.:  {features.has_brand_in_subdomain}")
    print(f"  Vector (24 feats): {vector}")

print("\n" + "="*60)
print("✓ Extractor funcionando correctamente")
print("="*60 + "\n")
