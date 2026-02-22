import requests
from urllib.parse import urlparse
import re

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPChecker:
    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }

    def check(self, domain: str) -> dict:
        result = {
            "http_status": None,
            "https_status": None,
            "page_title": None,
            "redirect_chain": [],
            "final_url": None,
            "server_header": None,
            "is_parked": False,
            "content_length": None,
        }

        for scheme in ["https", "http"]:
            url = f"{scheme}://{domain}"
            try:
                resp = requests.get(
                    url,
                    timeout=self.timeout,
                    headers=self.headers,
                    allow_redirects=True,
                    verify=False,  
                )

                status = resp.status_code
                if scheme == "https":
                    result["https_status"] = status
                else:
                    result["http_status"] = status

                if result.get("final_url") is None:
                    result["http_status"] = status
                    result["final_url"] = resp.url
                    result["server_header"] = resp.headers.get("Server")
                    result["content_length"] = len(resp.content)

                    result["redirect_chain"] = [r.url for r in resp.history]

                    content = resp.text[:5000]
                    title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        result["page_title"] = title_match.group(1).strip()

                    result["is_parked"] = self._is_parked(resp.text, resp.url)

                break  

            except requests.exceptions.SSLError:
                result[f"{scheme}_status"] = 495  
            except requests.exceptions.ConnectionError:
                pass
            except requests.exceptions.Timeout:
                pass
            except Exception:
                pass

        return result

    def _is_parked(self, content: str, url: str) -> bool:
        parked_indicators = [
            'domain for sale', 'this domain is for sale',
            'buy this domain', 'domain parking',
            'parked domain', 'sedo.com', 'godaddy.com/parking',
            'dan.com', 'afternic.com', 'undeveloped.com',
            'hugedomains.com', 'domainnameshop',
            'this domain may be for sale',
        ]
        content_lower = content.lower()
        url_lower = url.lower()

        for indicator in parked_indicators:
            if indicator in content_lower or indicator in url_lower:
                return True
        return False
