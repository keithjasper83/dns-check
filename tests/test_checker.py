"""Tests for DNS checker module."""

import pytest
from dns_check.checker import DNSChecker
import dns.resolver


class TestDNSChecker:
    """Test cases for DNSChecker class."""

    def test_initialization(self):
        """Test DNSChecker initialization."""
        checker = DNSChecker()
        assert checker.resolver is not None
        assert checker.resolver.timeout == 5.0

    def test_initialization_with_nameservers(self):
        """Test DNSChecker initialization with custom nameservers."""
        nameservers = ["8.8.8.8", "1.1.1.1"]
        checker = DNSChecker(nameservers=nameservers)
        assert checker.resolver.nameservers == nameservers

    def test_initialization_with_timeout(self):
        """Test DNSChecker initialization with custom timeout."""
        timeout = 10.0
        checker = DNSChecker(timeout=timeout)
        assert checker.resolver.timeout == timeout

    def test_lookup_a_record(self):
        """Test A record lookup for a known domain."""
        checker = DNSChecker()
        # Use a reliable public domain
        results = checker.lookup("google.com", "A")
        assert len(results) > 0
        # Basic validation that we got IP addresses
        for result in results:
            parts = result.split(".")
            assert len(parts) == 4  # IPv4 format

    def test_lookup_ns_record(self):
        """Test NS record lookup."""
        checker = DNSChecker()
        results = checker.get_nameservers("google.com")
        assert len(results) > 0

    def test_check_multiple(self):
        """Test checking multiple record types."""
        checker = DNSChecker()
        results = checker.check_multiple("google.com", ["A", "NS"])
        assert "A" in results
        assert "NS" in results
        assert results["A"]["success"] is True
        assert results["NS"]["success"] is True

    def test_check_multiple_with_invalid_type(self):
        """Test checking with an invalid record type."""
        checker = DNSChecker()
        results = checker.check_multiple("google.com", ["A", "INVALID"])
        assert "A" in results
        assert "INVALID" in results
        assert results["A"]["success"] is True
        assert results["INVALID"]["success"] is False

    def test_lookup_nonexistent_domain(self):
        """Test lookup for a non-existent domain."""
        checker = DNSChecker()
        with pytest.raises(dns.resolver.NXDOMAIN):
            checker.lookup("this-domain-definitely-does-not-exist-12345.com", "A")
