"""Tests for recon/uncover_enrich.py"""
import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'recon'))

from uncover_enrich import (
    _build_provider_config,
    _deduplicate_results,
    _extract_hosts_and_ips,
    _build_queries,
    merge_uncover_into_pipeline,
    run_uncover_expansion,
)


class TestBuildProviderConfig(unittest.TestCase):

    def test_empty_settings_returns_shodan_idb_only(self):
        config, engines = _build_provider_config({})
        self.assertEqual(config, {})
        self.assertEqual(engines, ['shodan-idb'])

    def test_shodan_key_adds_engine(self):
        config, engines = _build_provider_config({'SHODAN_API_KEY': 'key123'})
        self.assertIn('shodan', config)
        self.assertIn('shodan', engines)
        self.assertNotIn('shodan-idb', engines)

    def test_censys_needs_both_token_and_org(self):
        config, engines = _build_provider_config({'CENSYS_API_TOKEN': 'tok'})
        self.assertNotIn('censys', engines)
        config, engines = _build_provider_config({
            'CENSYS_API_TOKEN': 'tok',
            'CENSYS_ORG_ID': 'org',
        })
        self.assertIn('censys', engines)
        self.assertEqual(config['censys'], ['tok:org'])

    def test_google_needs_both_key_and_cx(self):
        config, engines = _build_provider_config({'UNCOVER_GOOGLE_API_KEY': 'gkey'})
        self.assertNotIn('google', engines)
        config, engines = _build_provider_config({
            'UNCOVER_GOOGLE_API_KEY': 'gkey',
            'UNCOVER_GOOGLE_API_CX': 'gcx',
        })
        self.assertIn('google', engines)
        self.assertEqual(config['google'], ['gkey:gcx'])

    def test_all_engines_configured(self):
        settings = {
            'SHODAN_API_KEY': 's1',
            'CENSYS_API_TOKEN': 'ct', 'CENSYS_ORG_ID': 'co',
            'FOFA_API_KEY': 'f1',
            'ZOOMEYE_API_KEY': 'z1',
            'NETLAS_API_KEY': 'n1',
            'CRIMINALIP_API_KEY': 'c1',
            'UNCOVER_QUAKE_API_KEY': 'q1',
            'UNCOVER_HUNTER_API_KEY': 'h1',
            'UNCOVER_PUBLICWWW_API_KEY': 'pw1',
            'UNCOVER_HUNTERHOW_API_KEY': 'hh1',
            'UNCOVER_GOOGLE_API_KEY': 'gk', 'UNCOVER_GOOGLE_API_CX': 'gc',
            'UNCOVER_ONYPHE_API_KEY': 'o1',
            'UNCOVER_DRIFTNET_API_KEY': 'd1',
        }
        config, engines = _build_provider_config(settings)
        expected = [
            'shodan', 'censys', 'fofa', 'zoomeye', 'netlas',
            'criminalip', 'quake', 'hunter', 'publicwww', 'hunterhow',
            'google', 'onyphe', 'driftnet',
        ]
        for e in expected:
            self.assertIn(e, engines, f"{e} missing from engines")
        self.assertNotIn('shodan-idb', engines)


class TestDeduplicateResults(unittest.TestCase):

    def test_dedup_by_ip_port(self):
        results = [
            {'ip': '1.2.3.4', 'port': 80, 'source': 'shodan'},
            {'ip': '1.2.3.4', 'port': 80, 'source': 'censys'},
            {'ip': '1.2.3.4', 'port': 443, 'source': 'shodan'},
            {'ip': '5.6.7.8', 'port': 80, 'source': 'fofa'},
        ]
        deduped = _deduplicate_results(results)
        self.assertEqual(len(deduped), 3)
        self.assertEqual(deduped[0]['source'], 'shodan')

    def test_skips_empty_ip(self):
        results = [
            {'ip': '', 'port': 80},
            {'ip': '1.2.3.4', 'port': 80},
        ]
        deduped = _deduplicate_results(results)
        self.assertEqual(len(deduped), 1)


class TestExtractHostsAndIps(unittest.TestCase):

    def test_filters_non_routable(self):
        results = [
            {'ip': '10.0.0.1', 'port': 80, 'host': 'internal.example.com'},
            {'ip': '93.184.216.34', 'port': 443, 'host': 'www.example.com'},
            {'ip': '100.64.1.5', 'port': 8080, 'host': 'cgnat.example.com'},
        ]
        ips, hosts, ip_ports = _extract_hosts_and_ips(
            results, 'example.com', {}
        )
        self.assertIn('93.184.216.34', ips)
        self.assertNotIn('10.0.0.1', ips)
        self.assertNotIn('100.64.1.5', ips)

    def test_extracts_in_scope_hostnames(self):
        results = [
            {'ip': '93.184.216.34', 'port': 443, 'host': 'sub.example.com'},
            {'ip': '1.2.3.4', 'port': 80, 'host': 'other.net'},
        ]
        ips, hosts, ip_ports = _extract_hosts_and_ips(
            results, 'example.com', {}
        )
        self.assertIn('sub.example.com', hosts)
        self.assertNotIn('other.net', hosts)

    def test_collects_ports_per_ip(self):
        results = [
            {'ip': '93.184.216.34', 'port': 80},
            {'ip': '93.184.216.34', 'port': 443},
        ]
        ips, hosts, ip_ports = _extract_hosts_and_ips(
            results, 'example.com', {}
        )
        self.assertEqual(sorted(ip_ports.get('93.184.216.34', [])), [80, 443])


class TestBuildQueries(unittest.TestCase):

    def test_basic_domain(self):
        queries = _build_queries('example.com', {})
        self.assertEqual(queries, ['example.com'])

    def test_with_whois_org(self):
        queries = _build_queries('example.com', {'_WHOIS_ORG': 'Example Inc.'})
        self.assertEqual(len(queries), 2)
        self.assertIn('ssl:"Example Inc."', queries)

    def test_skips_na_org(self):
        queries = _build_queries('example.com', {'_WHOIS_ORG': 'N/A'})
        self.assertEqual(len(queries), 1)


class TestMergeIntoPipeline(unittest.TestCase):

    def test_merge_new_subdomains(self):
        combined = {"dns": {"subdomains": {}}, "domain": "example.com"}
        uncover_data = {
            "hosts": ["new.example.com", "api.example.com"],
            "ips": ["1.2.3.4"],
            "ip_ports": {"1.2.3.4": [80, 443]},
        }
        count = merge_uncover_into_pipeline(combined, uncover_data, "example.com")
        self.assertGreater(count, 0)
        self.assertIn("new.example.com", combined["dns"]["subdomains"])
        self.assertIn("api.example.com", combined["dns"]["subdomains"])
        self.assertEqual(
            combined["dns"]["subdomains"]["new.example.com"]["source"],
            "uncover",
        )

    def test_no_duplicate_subdomains(self):
        combined = {
            "dns": {"subdomains": {"existing.example.com": {"ips": {"ipv4": []}}}},
            "domain": "example.com",
        }
        uncover_data = {
            "hosts": ["existing.example.com", "new.example.com"],
            "ips": [],
            "ip_ports": {},
        }
        count = merge_uncover_into_pipeline(combined, uncover_data, "example.com")
        self.assertGreater(count, 0)

    def test_empty_data(self):
        combined = {"dns": {"subdomains": {}}}
        count = merge_uncover_into_pipeline(combined, {}, "example.com")
        self.assertEqual(count, 0)


class TestRunUncoverExpansion(unittest.TestCase):

    def test_disabled_returns_empty(self):
        result = run_uncover_expansion({}, {'UNCOVER_ENABLED': False})
        self.assertEqual(result, {})

    def test_no_keys_returns_empty(self):
        result = run_uncover_expansion(
            {"domain": "example.com"},
            {'UNCOVER_ENABLED': True},
        )
        self.assertEqual(result, {})

    @patch('uncover_enrich.subprocess.run')
    def test_parses_json_output(self, mock_run):
        output_lines = [
            json.dumps({"ip": "93.184.216.34", "port": 443, "host": "www.example.com", "source": "shodan"}),
            json.dumps({"ip": "93.184.216.35", "port": 80, "host": "api.example.com", "source": "censys"}),
        ]
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "\n".join(output_lines)
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        settings = {
            'UNCOVER_ENABLED': True,
            'SHODAN_API_KEY': 'test_key',
            'UNCOVER_MAX_RESULTS': 100,
        }
        combined = {
            "domain": "example.com",
            "metadata": {"modules_executed": []},
        }
        result = run_uncover_expansion(combined, settings)
        self.assertIn("ips", result)
        self.assertIn("hosts", result)

    @patch('uncover_enrich.subprocess.run')
    def test_timeout_returns_partial(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=600)
        settings = {
            'UNCOVER_ENABLED': True,
            'SHODAN_API_KEY': 'test_key',
            'UNCOVER_MAX_RESULTS': 100,
        }
        combined = {
            "domain": "example.com",
            "metadata": {"modules_executed": []},
        }
        result = run_uncover_expansion(combined, settings)
        self.assertIsInstance(result, dict)


if __name__ == '__main__':
    unittest.main()
