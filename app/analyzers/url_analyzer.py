# app/analyzers/url_analyzer.py
import re
import math
import tldextract
import ipaddress
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class URLFeatures:
    # --- Features de longitud ---
    url_length: int = 0
    domain_length: int = 0
    path_length: int = 0
    subdomain_length: int = 0

    # --- Features de caracteres sospechosos ---
    num_dots: int = 0
    num_hyphens: int = 0
    num_underscores: int = 0
    num_at_symbols: int = 0
    num_question_marks: int = 0
    num_equals: int = 0
    num_slashes: int = 0
    num_percent: int = 0
    num_digits_in_domain: int = 0

    # --- Features de estructura ---
    has_ip_address: bool = False
    has_https: bool = False
    num_subdomains: int = 0
    has_suspicious_tld: bool = False
    is_shortened_url: bool = False
    has_port: bool = False

    # --- Features de contenido ---
    has_brand_in_subdomain: bool = False
    has_brand_in_path: bool = False
    entropy: float = 0.0
    digit_ratio: float = 0.0
    special_char_ratio: float = 0.0

    # --- Label (para entrenamiento) ---
    label: Optional[int] = None  # 1 = phishing, 0 = legítima


class URLAnalyzer:
    """
    Extrae features de una URL para clasificación de phishing.
    Cada feature fue elegida basada en papers de detección de phishing.
    """

    SUSPICIOUS_TLDS = {
        '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
        '.club', '.online', '.site', '.website', '.space',
        '.click', '.link', '.info'
    }

    SHORTENED_DOMAINS = {
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
        'is.gd', 'buff.ly', 'adf.ly', 'short.link', 'tiny.cc'
    }

    COMMON_BRANDS = [
        'paypal', 'google', 'facebook', 'apple', 'microsoft',
        'amazon', 'netflix', 'instagram', 'twitter', 'linkedin',
        'bank', 'secure', 'login', 'account', 'verify', 'update'
    ]

    def analyze(self, url: str) -> URLFeatures:
        features = URLFeatures()

        # Normalizar URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        parsed = urlparse(url)
        extracted = tldextract.extract(url)

        domain = extracted.domain
        subdomain = extracted.subdomain
        suffix = extracted.suffix
        full_domain = parsed.netloc
        path = parsed.path

        # ── Longitudes ──────────────────────────────────────────
        features.url_length = len(url)
        features.domain_length = len(domain)
        features.path_length = len(path)
        features.subdomain_length = len(subdomain)

        # ── Conteo de caracteres especiales ─────────────────────
        features.num_dots = url.count('.')
        features.num_hyphens = url.count('-')
        features.num_underscores = url.count('_')
        features.num_at_symbols = url.count('@')
        features.num_question_marks = url.count('?')
        features.num_equals = url.count('=')
        features.num_slashes = url.count('/')
        features.num_percent = url.count('%')
        features.num_digits_in_domain = sum(c.isdigit() for c in domain)

        # ── Estructura ───────────────────────────────────────────
        features.has_https = parsed.scheme == 'https'
        features.has_port = bool(parsed.port)
        features.num_subdomains = len(subdomain.split('.')) if subdomain else 0

        # ¿Es una IP en vez de dominio?
        features.has_ip_address = self._is_ip_address(full_domain)

        # ¿TLD sospechoso?
        features.has_suspicious_tld = f'.{suffix}' in self.SUSPICIOUS_TLDS

        # ¿URL acortada?
        features.is_shortened_url = any(
            s in full_domain for s in self.SHORTENED_DOMAINS
        )

        # ── Contenido y marcas ───────────────────────────────────
        features.has_brand_in_subdomain = any(
            brand in subdomain.lower() for brand in self.COMMON_BRANDS
        )
        features.has_brand_in_path = any(
            brand in path.lower() for brand in self.COMMON_BRANDS
        )

        # ── Métricas de entropía y ratios ────────────────────────
        features.entropy = self._shannon_entropy(domain)
        features.digit_ratio = (
            sum(c.isdigit() for c in url) / len(url) if url else 0
        )
        special_chars = sum(not c.isalnum() for c in url)
        features.special_char_ratio = special_chars / len(url) if url else 0

        return features

    def to_vector(self, features: URLFeatures) -> list:
        """Convierte features a vector numérico para el modelo ML."""
        return [
            features.url_length,
            features.domain_length,
            features.path_length,
            features.subdomain_length,
            features.num_dots,
            features.num_hyphens,
            features.num_underscores,
            features.num_at_symbols,
            features.num_question_marks,
            features.num_equals,
            features.num_slashes,
            features.num_percent,
            features.num_digits_in_domain,
            int(features.has_ip_address),
            int(features.has_https),
            features.num_subdomains,
            int(features.has_suspicious_tld),
            int(features.is_shortened_url),
            int(features.has_port),
            int(features.has_brand_in_subdomain),
            int(features.has_brand_in_path),
            features.entropy,
            features.digit_ratio,
            features.special_char_ratio,
        ]

    def _is_ip_address(self, host: str) -> bool:
        """Detecta si el host es una IP (técnica de evasión común en phishing)."""
        host = host.split(':')[0]  # Remover puerto si existe
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _shannon_entropy(self, text: str) -> float:
        """
        Entropía de Shannon — URLs phishing suelen tener alta entropía
        por strings aleatorios generados automáticamente.
        """
        if not text:
            return 0.0
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        entropy = 0.0
        for count in freq.values():
            prob = count / len(text)
            entropy -= prob * math.log2(prob)
        return round(entropy, 4)