"""DNS checker module for performing DNS lookups and analysis."""

import dns.resolver
from typing import List, Dict, Any, Optional


class DNSChecker:
    """Main class for DNS checking and analysis."""

    def __init__(self, nameservers: Optional[List[str]] = None, timeout: float = 5.0):
        """
        Initialize DNS checker.

        Args:
            nameservers: List of DNS nameservers to use. If None, uses system defaults.
            timeout: Timeout for DNS queries in seconds.
        """
        self.resolver = dns.resolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def lookup(
        self, domain: str, record_type: str = "A"
    ) -> List[str]:
        """
        Perform DNS lookup for a domain.

        Args:
            domain: Domain name to lookup.
            record_type: DNS record type (A, AAAA, MX, TXT, NS, etc.).

        Returns:
            List of DNS records as strings.

        Raises:
            dns.resolver.NXDOMAIN: Domain does not exist.
            dns.resolver.NoAnswer: No DNS records found.
            dns.resolver.Timeout: DNS query timed out.
        """
        results = []
        answers = self.resolver.resolve(domain, record_type)
        for rdata in answers:
            results.append(str(rdata))
        return results

    def check_multiple(
        self, domain: str, record_types: List[str]
    ) -> Dict[str, Any]:
        """
        Check multiple DNS record types for a domain.

        Args:
            domain: Domain name to lookup.
            record_types: List of DNS record types to check.

        Returns:
            Dictionary mapping record types to their results or errors.
        """
        results = {}
        for record_type in record_types:
            try:
                records = self.lookup(domain, record_type)
                results[record_type] = {"success": True, "records": records}
            except dns.resolver.NXDOMAIN:
                results[record_type] = {"success": False, "error": "Domain does not exist"}
            except dns.resolver.NoAnswer:
                results[record_type] = {"success": False, "error": "No answer"}
            except dns.resolver.Timeout:
                results[record_type] = {"success": False, "error": "Timeout"}
            except Exception as e:
                results[record_type] = {"success": False, "error": str(e)}
        return results

    def get_nameservers(self, domain: str) -> List[str]:
        """
        Get authoritative nameservers for a domain.

        Args:
            domain: Domain name to check.

        Returns:
            List of authoritative nameserver hostnames.
        """
        return self.lookup(domain, "NS")
