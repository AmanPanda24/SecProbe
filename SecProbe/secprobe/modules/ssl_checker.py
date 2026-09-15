"""
SecProbe - SSL/TLS Configuration Scanner Module
Checks for certificate validity, weak ciphers, and protocol issues.
"""

import ssl
import socket
import datetime
from typing import Optional


class SSLChecker:
    def __init__(self, hostname: str, port: int = 443, timeout: int = 10):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

    def scan(self) -> list:
        issues = []
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()

                    # Check certificate expiry
                    expiry_issues = self._check_expiry(cert)
                    issues.extend(expiry_issues)

                    # Check protocol version
                    proto_issues = self._check_protocol(protocol)
                    issues.extend(proto_issues)

                    # Check cipher strength
                    cipher_issues = self._check_cipher(cipher)
                    issues.extend(cipher_issues)

                    # Check SANs / hostname match
                    san_issues = self._check_san(cert)
                    issues.extend(san_issues)

        except ssl.SSLCertVerificationError as e:
            issues.append({
                "type": "Invalid SSL Certificate",
                "severity": "Critical",
                "impact": "Certificate is invalid or untrusted, enabling MITM attacks.",
                "fix": "Renew or obtain a valid certificate from a trusted CA.",
                "category": "SSL/TLS",
                "detail": str(e),
            })
        except ssl.SSLError as e:
            issues.append({
                "type": "SSL Error",
                "severity": "High",
                "impact": "SSL handshake failed; connection security cannot be verified.",
                "fix": "Review SSL configuration and certificate setup.",
                "category": "SSL/TLS",
                "detail": str(e),
            })
        except ConnectionRefusedError:
            issues.append({
                "type": "HTTPS Not Available",
                "severity": "Critical",
                "impact": "No HTTPS listener on port 443; all traffic sent unencrypted.",
                "fix": "Configure a web server with TLS and obtain a valid certificate.",
                "category": "SSL/TLS",
            })
        except socket.timeout:
            issues.append({
                "type": "SSL Connection Timeout",
                "severity": "Info",
                "impact": "SSL port timed out; could not verify TLS configuration.",
                "fix": "Ensure the server is reachable and port 443 is open.",
                "category": "SSL/TLS",
            })
        except Exception as e:
            issues.append({
                "type": "SSL Check Failed",
                "severity": "Info",
                "impact": "Could not complete SSL/TLS scan.",
                "fix": "Manually verify the SSL configuration.",
                "category": "SSL/TLS",
                "detail": str(e),
            })

        return issues

    def _check_expiry(self, cert: dict) -> list:
        issues = []
        not_after = cert.get("notAfter")
        if not_after:
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days

            if days_left < 0:
                issues.append({
                    "type": "Expired SSL Certificate",
                    "severity": "Critical",
                    "impact": f"Certificate expired {abs(days_left)} days ago. Browsers show security warnings.",
                    "fix": "Renew your SSL certificate immediately.",
                    "category": "SSL/TLS",
                })
            elif days_left < 14:
                issues.append({
                    "type": "SSL Certificate Expiring Soon",
                    "severity": "High",
                    "impact": f"Certificate expires in {days_left} days. Site will become unreachable.",
                    "fix": "Renew your SSL certificate before it expires.",
                    "category": "SSL/TLS",
                })
            elif days_left < 30:
                issues.append({
                    "type": "SSL Certificate Expiring Soon",
                    "severity": "Medium",
                    "impact": f"Certificate expires in {days_left} days.",
                    "fix": "Schedule certificate renewal within the next 30 days.",
                    "category": "SSL/TLS",
                })
        return issues

    def _check_protocol(self, protocol: Optional[str]) -> list:
        issues = []
        weak_protocols = {"TLSv1": "High", "TLSv1.1": "High", "SSLv2": "Critical", "SSLv3": "Critical"}
        if protocol in weak_protocols:
            issues.append({
                "type": f"Weak Protocol: {protocol}",
                "severity": weak_protocols[protocol],
                "impact": f"{protocol} has known vulnerabilities (e.g. POODLE, BEAST).",
                "fix": "Disable deprecated protocols. Enable TLS 1.2 and TLS 1.3 only.",
                "category": "SSL/TLS",
            })
        return issues

    def _check_cipher(self, cipher: Optional[tuple]) -> list:
        issues = []
        if not cipher:
            return issues
        cipher_name = cipher[0] if cipher else ""
        weak_keywords = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]
        for kw in weak_keywords:
            if kw in cipher_name.upper():
                issues.append({
                    "type": f"Weak Cipher Suite: {cipher_name}",
                    "severity": "High",
                    "impact": f"Cipher {cipher_name} is cryptographically weak and breakable.",
                    "fix": "Configure server to use only strong cipher suites (AES-GCM, ChaCha20).",
                    "category": "SSL/TLS",
                })
                break
        return issues

    def _check_san(self, cert: dict) -> list:
        issues = []
        san = cert.get("subjectAltName")
        if not san:
            issues.append({
                "type": "Missing Subject Alternative Name",
                "severity": "Medium",
                "impact": "Certificate lacks SAN; modern browsers will reject it.",
                "fix": "Reissue the certificate with proper SAN entries.",
                "category": "SSL/TLS",
            })
        return issues
