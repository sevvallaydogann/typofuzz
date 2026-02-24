"""
Risk Scoring Engine
Calculates a composite risk score (0-100) for each domain variation
based on multiple signals.
"""

class RiskScorer:
    """
    Risk Score Breakdown:
    ─────────────────────────────────────────────
    Signal                          Max Points
    ─────────────────────────────────────────────
    Domain is registered                  20
    Active HTTP website                   15
    Has MX records (email phishing)       20
    Valid SSL certificate                 10
    Recently registered (<90 days)        15
    Threat Intel hit (VT/URLhaus/OTX)     30
    Parked domain (lower risk)            -5
    Homoglyph/IDN variation               +5
    Subdomain abuse pattern               +3
    Combosquatting with login keywords    +5
    ─────────────────────────────────────────────
    Max Score:                           100
    ─────────────────────────────────────────────
    Thresholds:
      70-100: HIGH RISK   🔴
      40-69:  MEDIUM RISK 🟡
      10-39:  LOW RISK    🟢
       0-9:   MINIMAL     ⚪
    """

    HIGH_RISK_COMBO_KEYWORDS = [
        'login', 'signin', 'account', 'secure', 'verify', 'update',
        'password', 'bank', 'pay', 'wallet', 'crypto', 'support',
        'official', 'confirm', 'authenticate',
    ]

    def score(self, domain_info: dict) -> int:
        score = 0
        vtype = domain_info.get("variation_type", "")

        # Registration status
        if domain_info.get("registered"):
            score += 20

        # Active website 
        http_status = domain_info.get("http_status")
        if http_status and http_status < 400:
            score += 15
        elif http_status and http_status in [301, 302, 307, 308]:
            score += 8  # Redirect may be phishing

        # MX records (email phishing potential)
        if domain_info.get("mx_records"):
            score += 20

        # SSL Certificate 
        if domain_info.get("ssl_valid"):
            score += 10
        if domain_info.get("ssl_self_signed"):
            score += 5  # Self-signed = suspicious

        # Recently registered
        if domain_info.get("recently_registered"):
            score += 15

        # Threat intelligence 
        if domain_info.get("is_threat"):
            score += 30
        elif domain_info.get("vt_detections") and domain_info["vt_detections"] > 0:
            score += min(domain_info["vt_detections"] * 3, 25)
        if domain_info.get("otx_pulses") and domain_info["otx_pulses"] > 0:
            score += min(domain_info["otx_pulses"] * 2, 15)

        # Parked domain (less risky) 
        if domain_info.get("is_parked"):
            score = max(0, score - 5)

        # Variation type modifiers 
        if vtype in ["homoglyph"]:
            score += 5  # Homoglyphs are more sophisticated/dangerous
        if vtype == "subdomain-abuse":
            score += 3
        if vtype == "combosquatting":
            domain = domain_info.get("domain", "")
            for kw in self.HIGH_RISK_COMBO_KEYWORDS:
                if kw in domain:
                    score += 5
                    break

        # Page title analysis 
        title = (domain_info.get("page_title") or "").lower()
        suspicious_title_words = ['login', 'sign in', 'account', 'verify', 'secure', 'bank', 'paypal']
        for word in suspicious_title_words:
            if word in title:
                score += 5
                break

        return min(score, 100)

    def classify(self, score: int) -> str:
        if score >= 70:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 10:
            return "LOW"
        else:
            return "MINIMAL"
