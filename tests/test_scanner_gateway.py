"""Unit tests for scanner/gateway.py. No network calls -- subprocess.run (the curl invocation) is
mocked throughout; every canned response body is verbatim or structurally identical to a real
response captured live against https://mainnet.radixdlt.com (see examples/posture-scanner/ and
docs/posture-scanner.md for provenance).
"""
import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from scanner import gateway  # noqa: E402


def _fake_completed(stdout, returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=["curl"], returncode=returncode, stdout=stdout, stderr=stderr)


class TestPost(unittest.TestCase):
    def test_parses_200_body_and_status(self):
        body = json.dumps({"ok": True})
        with patch("scanner.gateway.subprocess.run", return_value=_fake_completed(body + "\n__HTTP_STATUS__:200")):
            status, parsed, raw = gateway._post(gateway.GATEWAY_URL_MAINNET, "/status/gateway-status", {})
        self.assertEqual(status, 200)
        self.assertEqual(parsed, {"ok": True})

    def test_curl_nonzero_exit_raises(self):
        with patch("scanner.gateway.subprocess.run", return_value=_fake_completed("", returncode=7, stderr="couldn't connect")):
            with self.assertRaises(gateway.GatewayError):
                gateway._post(gateway.GATEWAY_URL_MAINNET, "/status/gateway-status", {})

    def test_missing_status_marker_raises(self):
        with patch("scanner.gateway.subprocess.run", return_value=_fake_completed("not what we expected")):
            with self.assertRaises(gateway.GatewayError):
                gateway._post(gateway.GATEWAY_URL_MAINNET, "/status/gateway-status", {})

    def test_curl_not_installed_raises_gateway_error(self):
        with patch("scanner.gateway.subprocess.run", side_effect=FileNotFoundError()):
            with self.assertRaises(gateway.GatewayError):
                gateway._post(gateway.GATEWAY_URL_MAINNET, "/status/gateway-status", {})


class TestGatewayStatus(unittest.TestCase):
    LIVE_BODY = (
        '{"ledger_state":{"network":"mainnet","state_version":557840622,'
        '"proposer_round_timestamp":"2026-08-31T21:19:06.179Z","epoch":339896,"round":102},'
        '"release_info":{"release_version":"1.10.6-v1.10.7"}}\n__HTTP_STATUS__:200'
    )

    def test_returns_ledger_state(self):
        with patch("scanner.gateway.subprocess.run", return_value=_fake_completed(self.LIVE_BODY)):
            result = gateway.gateway_status()
        self.assertEqual(result["ledger_state"]["state_version"], 557840622)

    def test_get_not_post_is_refused_405_would_raise(self):
        # Confirmed live: an unadorned GET to this endpoint returns HTTP 405. This test locks in
        # that _post always issues POST (curl -X POST), which is why gateway_status() works.
        with patch("scanner.gateway.subprocess.run") as mock_run:
            mock_run.return_value = _fake_completed(self.LIVE_BODY)
            gateway.gateway_status()
            args = mock_run.call_args[0][0]
            self.assertIn("-X", args)
            self.assertEqual(args[args.index("-X") + 1], "POST")


class TestEntityDetailsNotSyncedUp(unittest.TestCase):
    # Verbatim shape captured live from an unpinned /state/entity/details call
    # during the halt (see examples/posture-scanner/error_not_synced_up.json).
    HALT_BODY = (
        '{"message":"The Gateway API cannot return current results as its database is not '
        'sufficiently up to date with the Network\'s Ledger (it is currently 7 days, 1 hour, 7 '
        'minutes, 56 seconds behind)","code":500,"details":{"request_type":"Read",'
        '"current_sync_delay_seconds":608876,"max_allowed_sync_delay_seconds":720,'
        '"type":"NotSyncedUpError"},"trace_id":"00-abc-def-00"}\n__HTTP_STATUS__:500'
    )

    def test_unpinned_call_raises_not_synced_up_error(self):
        with patch("scanner.gateway.subprocess.run", return_value=_fake_completed(self.HALT_BODY)):
            with self.assertRaises(gateway.NotSyncedUpError) as ctx:
                gateway.entity_details(["resource_rdx1tknxxxxxxxxxradxrdxxxxxxxxx009923554798xxxxxxxxxradxrd"], 1)
        self.assertEqual(ctx.exception.current_sync_delay_seconds, 608876)
        self.assertEqual(ctx.exception.max_allowed_sync_delay_seconds, 720)

    def test_probe_halted_returns_true_and_detail(self):
        with patch("scanner.gateway.subprocess.run", return_value=_fake_completed(self.HALT_BODY)):
            halted, detail = gateway.probe_halted()
        self.assertTrue(halted)
        self.assertIn("not sufficiently up to date", detail)

    def test_probe_halted_false_on_clean_200(self):
        ok_body = (
            '{"ledger_state":{"network":"mainnet","state_version":1,"epoch":1,"round":1},'
            '"items":[]}\n__HTTP_STATUS__:200'
        )
        with patch("scanner.gateway.subprocess.run", return_value=_fake_completed(ok_body)):
            halted, detail = gateway.probe_halted()
        self.assertFalse(halted)
        self.assertIsNone(detail)

    def test_probe_halted_never_raises_on_generic_gateway_error(self):
        with patch("scanner.gateway.subprocess.run", side_effect=FileNotFoundError()):
            halted, detail = gateway.probe_halted()
        self.assertFalse(halted)
        self.assertIsNone(detail)


class TestEntityDetailsByAddress(unittest.TestCase):
    def test_indexes_by_address_not_position(self):
        body = (
            '{"ledger_state":{"state_version":1},"items":['
            '{"address":"resource_rdx1bbb"},{"address":"account_rdx1aaa"}'
            ']}\n__HTTP_STATUS__:200'
        )
        with patch("scanner.gateway.subprocess.run", return_value=_fake_completed(body)):
            result = gateway.entity_details_by_address(["account_rdx1aaa", "resource_rdx1bbb"], 1)
        self.assertEqual(set(result), {"account_rdx1aaa", "resource_rdx1bbb"})
        self.assertEqual(result["account_rdx1aaa"]["address"], "account_rdx1aaa")

    def test_missing_address_in_response_raises(self):
        body = '{"ledger_state":{"state_version":1},"items":[{"address":"account_rdx1aaa"}]}\n__HTTP_STATUS__:200'
        with patch("scanner.gateway.subprocess.run", return_value=_fake_completed(body)):
            with self.assertRaises(gateway.GatewayError):
                gateway.entity_details_by_address(["account_rdx1aaa", "account_rdx1missing"], 1)

    def test_uses_vault_aggregation_never_global(self):
        body = '{"ledger_state":{"state_version":1},"items":[{"address":"account_rdx1aaa"}]}\n__HTTP_STATUS__:200'
        with patch("scanner.gateway.subprocess.run") as mock_run:
            mock_run.return_value = _fake_completed(body)
            gateway.entity_details_by_address(["account_rdx1aaa"], 1)
            sent = json.loads(mock_run.call_args[0][0][mock_run.call_args[0][0].index("-d") + 1])
        self.assertEqual(sent["aggregation_level"], "Vault")
        self.assertEqual(sent["at_ledger_state"], {"state_version": 1})

    def test_empty_addresses_rejected(self):
        with self.assertRaises(ValueError):
            gateway.entity_details([], 1)


if __name__ == "__main__":
    unittest.main()
