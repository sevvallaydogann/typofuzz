import whois
from datetime import datetime

class WHOISChecker:
    def check(self, domain: str) -> dict:
        result = {
            "whois_registrar": None,
            "whois_creation_date": None,
            "whois_expiry_date": None,
            "whois_country": None,
            "whois_emails": [],
            "whois_name_servers": [],
            "recently_registered": False,
        }

        try:
            w = whois.whois(domain)

            result["whois_registrar"] = str(w.registrar) if w.registrar else None
            result["whois_country"] = str(w.country) if hasattr(w, "country") else None

            # Creation date
            creation = w.creation_date
            if creation:
                if isinstance(creation, list):
                    creation = creation[0]
                result["whois_creation_date"] = str(creation)
                # Flag recently registered (<90 days) domains as higher risk
                if isinstance(creation, datetime):
                    age_days = (datetime.now() - creation.replace(tzinfo=None)).days
                    result["recently_registered"] = age_days < 90

            # Expiry date
            expiry = w.expiration_date
            if expiry:
                if isinstance(expiry, list):
                    expiry = expiry[0]
                result["whois_expiry_date"] = str(expiry)

            # Emails
            if w.emails:
                emails = w.emails if isinstance(w.emails, list) else [w.emails]
                result["whois_emails"] = [str(e) for e in emails if e]

            # Name servers
            if w.name_servers:
                ns = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
                result["whois_name_servers"] = [str(s).lower() for s in ns if s]

        except Exception:
            pass

        return result
