import requests
import time

class ThreatIntelChecker:
    
    def __init__(self, vt_api_key: str = None, timeout: float = 10.0):
        self.vt_api_key = vt_api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "TypoFuzz-OSINT/1.0"
        })
        
        self.last_vt_request = 0.0

    def check(self, domain: str) -> dict:
        result = {
            "is_threat": False,
            "threat_sources": [],
            "vt_detections": None,
            "vt_reputation": None,
            "urlhaus_status": None,
            "otx_pulses": None,
            "threat_categories": [],
        }

        if self.vt_api_key:
            vt_result = self._check_virustotal(domain)
            result.update(vt_result)

        urlhaus_result = self._check_urlhaus(domain)
        result.update(urlhaus_result)

        otx_result = self._check_otx(domain)
        result.update(otx_result)

        result["is_threat"] = (
            (result.get("vt_detections") and result["vt_detections"] > 0)
            or result.get("urlhaus_status") == "malicious"
            or bool(result.get("otx_pulses") and result["otx_pulses"] > 0)
        )

        return result

    def _check_virustotal(self, domain: str) -> dict:
        """VirusTotal API v3 - Rate Limited"""
        result = {}
        
        time_since_last = time.time() - self.last_vt_request
        if time_since_last < 15.0:
            wait_time = 15.0 - time_since_last
            print(f"[*] VirusTotal rate limit protection: Waiting for {wait_time:.1f} seconds...")
            time.sleep(wait_time)

        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            resp = self.session.get(
                url,
                headers={"x-apikey": self.vt_api_key},
                timeout=self.timeout,
            )
            
            self.last_vt_request = time.time()

            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                
                result["vt_detections"] = stats.get("malicious", 0) + stats.get("suspicious", 0)
                result["vt_reputation"] = attrs.get("reputation", 0)

                categories = attrs.get("categories", {})
                if categories:
                    result["threat_categories"] = list(set(categories.values()))

                if result.get("vt_detections", 0) > 0:
                    result["threat_sources"] = ["VirusTotal"]
        except Exception:
            pass
        return result

    def _check_urlhaus(self, domain: str) -> dict:
        """URLhaus (Abuse.ch) - Malware Detection"""
        result = {}
        try:
            resp = self.session.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": domain},
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                query_status = data.get("query_status", "")
                if query_status == "is_host":
                    result["urlhaus_status"] = "malicious"
                    result["threat_sources"] = ["URLhaus"]
                elif query_status == "no_results":
                    result["urlhaus_status"] = "clean"
        except Exception:
            pass
        return result

    def _check_otx(self, domain: str) -> dict:
        """AlienVault OTX - Cyber Intelligence Signals"""
        result = {}
        try:
            resp = self.session.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                result["otx_pulses"] = pulse_count
                if pulse_count > 0:
                    result["threat_sources"] = result.get("threat_sources", []) + ["AlienVault OTX"]
        except Exception:
            pass
        return result