import ssl
import socket
from datetime import datetime, timezone


class SSLChecker:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def check(self, domain: str) -> dict:
        result = {
            "ssl_valid": False,
            "ssl_issuer": None,
            "ssl_subject": None,
            "ssl_expiry": None,
            "ssl_san": [],
            "ssl_days_remaining": None,
            "ssl_self_signed": False,
            "ssl_wildcard": False,
            "ssl_grade": None,
        }

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_OPTIONAL

            conn = socket.create_connection((domain, 443), timeout=self.timeout)
            sock = context.wrap_socket(conn, server_hostname=domain)
            cert = sock.getpeercert()
            sock.close()

            if not cert:
                return result

            result["ssl_valid"] = True

            # Subject
            subject = dict(x[0] for x in cert.get('subject', []))
            result["ssl_subject"] = subject.get('commonName')

            # Issuer
            issuer = dict(x[0] for x in cert.get('issuer', []))
            issuer_org = issuer.get('organizationName', issuer.get('commonName', ''))
            result["ssl_issuer"] = issuer_org

            # Self-signed detection
            result["ssl_self_signed"] = (
                subject.get('commonName') == issuer.get('commonName')
            )

            # SAN (Subject Alternative Names)
            san = cert.get('subjectAltName', [])
            result["ssl_san"] = [name for _, name in san]

            # Wildcard cert
            result["ssl_wildcard"] = any(
                name.startswith('*.') for name in result["ssl_san"]
            )

            # Expiry
            expiry_str = cert.get('notAfter')
            if expiry_str:
                try:
                    expiry = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                    expiry = expiry.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    result["ssl_expiry"] = expiry.isoformat()
                    result["ssl_days_remaining"] = (expiry - now).days
                except Exception:
                    pass

            # Grade assignment
            result["ssl_grade"] = self._grade_ssl(result)

        except ssl.SSLCertVerificationError:
            result["ssl_valid"] = False
            result["ssl_self_signed"] = True
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        except Exception:
            pass

        return result

    def _grade_ssl(self, info: dict) -> str:
        """Simple SSL grade based on cert properties."""
        if info["ssl_self_signed"]:
            return "F"
        if info["ssl_days_remaining"] and info["ssl_days_remaining"] < 0:
            return "F"
        if info["ssl_days_remaining"] and info["ssl_days_remaining"] < 30:
            return "C"
        known_issuers = ["Let's Encrypt", "DigiCert", "GlobalSign", "Comodo", "Sectigo", "Amazon"]
        if any(ki in (info["ssl_issuer"] or "") for ki in known_issuers):
            return "A"
        return "B"
