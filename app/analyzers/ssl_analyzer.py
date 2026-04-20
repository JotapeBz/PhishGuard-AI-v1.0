# app/analyzers/ssl_analyzer.py
import ssl
import socket
import datetime
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

@dataclass
class SSLResult:
    has_ssl: bool = False
    cert_valid: bool = False
    days_until_expiry: int = 0
    issuer: str = ""
    is_self_signed: bool = False
    cert_age_days: int = 0
    domain_matches: bool = False
    risk_score: float = 0.0
    warnings: list = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []

class SSLAnalyzer:
    """
    Analiza el certificado SSL de un dominio.
    Los sitios de phishing suelen tener certs recién emitidos,
    auto-firmados, o con discrepancias en el dominio.
    """

    def analyze(self, url: str) -> SSLResult:
        result = SSLResult()
        parsed = urlparse(url if url.startswith('http') else 'https://' + url)
        hostname = parsed.hostname

        if not hostname:
            result.warnings.append("No se pudo extraer hostname")
            return result

        result.has_ssl = parsed.scheme == 'https'
        if not result.has_ssl:
            result.warnings.append("Sin HTTPS — alto riesgo")
            result.risk_score = 0.8
            return result

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    result.cert_valid = True
                    result = self._parse_cert(result, cert, hostname)

        except ssl.SSLCertVerificationError:
            result.cert_valid = False
            result.warnings.append("Certificado inválido o no verificable")
            result.risk_score = 0.9

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            result.warnings.append(f"No se pudo conectar: {str(e)[:40]}")
            result.risk_score = 0.5

        return result

    def _parse_cert(self, result: SSLResult, cert: dict, hostname: str) -> SSLResult:
        now = datetime.datetime.utcnow()

        # Fecha de expiración
        expire_str = cert.get('notAfter', '')
        if expire_str:
            expire_date = datetime.datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
            result.days_until_expiry = (expire_date - now).days
            if result.days_until_expiry < 30:
                result.warnings.append(f"Cert expira en {result.days_until_expiry} días")

        # Fecha de emisión → certs recientes son sospechosos
        start_str = cert.get('notBefore', '')
        if start_str:
            start_date = datetime.datetime.strptime(start_str, '%b %d %H:%M:%S %Y %Z')
            result.cert_age_days = (now - start_date).days
            if result.cert_age_days < 30:
                result.warnings.append(f"Cert muy reciente: {result.cert_age_days} días")

        # Emisor
        issuer_dict = dict(x[0] for x in cert.get('issuer', []))
        result.issuer = issuer_dict.get('organizationName', 'Desconocido')
        result.is_self_signed = (
            issuer_dict.get('commonName', '') == hostname or
            result.issuer in ('', 'Desconocido')
        )
        if result.is_self_signed:
            result.warnings.append("Certificado auto-firmado")

        # ¿El dominio del cert coincide?
        san = cert.get('subjectAltName', [])
        valid_domains = [v for t, v in san if t == 'DNS']
        result.domain_matches = any(
            self._domain_matches(hostname, d) for d in valid_domains
        )
        if not result.domain_matches:
            result.warnings.append("Dominio no coincide con el certificado")

        # Calcular risk score
        result.risk_score = self._calculate_risk(result)
        return result

    def _domain_matches(self, hostname: str, cert_domain: str) -> bool:
        if cert_domain.startswith('*.'):
            suffix = cert_domain[2:]
            return hostname.endswith(suffix)
        return hostname == cert_domain

    def _calculate_risk(self, r: SSLResult) -> float:
        score = 0.0
        if not r.cert_valid:       score += 0.4
        if r.is_self_signed:       score += 0.3
        if not r.domain_matches:   score += 0.2
        if r.cert_age_days < 30:   score += 0.15
        if r.days_until_expiry < 30: score += 0.1
        return min(round(score, 2), 1.0)