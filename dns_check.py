import socket
import dns.resolver
import dns.exception

class DNSChecker:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def check(self, domain: str) -> dict:
        result = {
            "registered": False,
            "ip_address": None,
            "ipv6_address": None,
            "mx_records": [],
            "ns_records": [],
            "a_records": [],
            "txt_records": [],
            "cname_record": None,
        }

        # A Record (IPv4)
        try:
            answers = self.resolver.resolve(domain, 'A')
            result["a_records"] = [str(r) for r in answers]
            result["ip_address"] = result["a_records"][0] if result["a_records"] else None
            result["registered"] = True
        except (dns.exception.DNSException, Exception):
            pass

        # AAAA Record (IPv6)
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            result["ipv6_address"] = str(answers[0])
            result["registered"] = True
        except (dns.exception.DNSException, Exception):
            pass

        # MX Record
        try:
            answers = self.resolver.resolve(domain, 'MX')
            result["mx_records"] = [str(r.exchange) for r in answers]
            if result["mx_records"]:
                result["registered"] = True
        except (dns.exception.DNSException, Exception):
            pass

        # NS Record
        try:
            answers = self.resolver.resolve(domain, 'NS')
            result["ns_records"] = [str(r) for r in answers]
            if result["ns_records"]:
                result["registered"] = True
        except (dns.exception.DNSException, Exception):
            pass

        # CNAME
        try:
            answers = self.resolver.resolve(domain, 'CNAME')
            result["cname_record"] = str(answers[0].target)
            result["registered"] = True
        except (dns.exception.DNSException, Exception):
            pass

        # TXT 
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            result["txt_records"] = [str(r) for r in answers]
        except (dns.exception.DNSException, Exception):
            pass

        return result
