"""Tests for CLI module."""

import pytest
from dns_check.cli import main
from unittest.mock import patch
import sys


class TestCLI:
    """Test cases for CLI functionality."""

    def test_main_with_domain(self, capsys):
        """Test CLI with basic domain argument."""
        with patch.object(sys, 'argv', ['dns-check', 'google.com']):
            result = main()
            assert result == 0
            captured = capsys.readouterr()
            assert "google.com" in captured.out
            assert "A Records:" in captured.out

    def test_main_with_multiple_types(self, capsys):
        """Test CLI with multiple record types."""
        with patch.object(sys, 'argv', ['dns-check', 'google.com', '-t', 'A', '-t', 'NS']):
            result = main()
            assert result == 0
            captured = capsys.readouterr()
            assert "A Records:" in captured.out
            assert "NS Records:" in captured.out

    def test_main_with_json_output(self, capsys):
        """Test CLI with JSON output."""
        with patch.object(sys, 'argv', ['dns-check', 'google.com', '--json']):
            result = main()
            assert result == 0
            captured = capsys.readouterr()
            # JSON output should contain these keys
            assert '"A"' in captured.out
            assert '"success"' in captured.out

    def test_main_with_custom_server(self, capsys):
        """Test CLI with custom DNS server."""
        with patch.object(sys, 'argv', ['dns-check', 'google.com', '-s', '8.8.8.8']):
            result = main()
            assert result == 0
            captured = capsys.readouterr()
            assert "google.com" in captured.out

    def test_main_with_timeout(self, capsys):
        """Test CLI with custom timeout."""
        with patch.object(sys, 'argv', ['dns-check', 'google.com', '--timeout', '10']):
            result = main()
            assert result == 0
            captured = capsys.readouterr()
            assert "google.com" in captured.out

    def test_version_argument(self, capsys):
        """Test --version argument."""
        with patch.object(sys, 'argv', ['dns-check', '--version']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0
            captured = capsys.readouterr()
            assert "dns-check" in captured.out
