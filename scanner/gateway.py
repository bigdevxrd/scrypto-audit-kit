"""Radix Gateway client: pinned entity reads + halt detection, over `curl`.

Why curl and not urllib/requests: this project's local dev machine cannot verify TLS
certificates from Python's own certificate store (a known-broken local install, not a Radix or
Gateway issue), and the deterministic core of this kit is stdlib-only by design (no `requests`
dependency). curl uses the system's own certificate store and works fine here. Every request
this module makes is POST with a JSON body -- confirmed live: an unadorned GET to
/status/gateway-status returns 405, and the Gateway's own OpenAPI spec describes every endpoint
this way, so this is not a workaround, it's the actual contract.

Two endpoints, both confirmed live against https://mainnet.radixdlt.com:

- POST /status/gateway-status  (no body fields required; {} is enough) -- works UNPINNED even
  during the halt. This is how the scanner discovers what state_version to pin every other read
  to, each run -- see gateway_status().
- POST /state/entity/details   (addresses: [...], aggregation_level, at_ledger_state) -- refused
  with a NotSyncedUpError (HTTP 500) when called unpinned during a halt; returns pinned reads
  cleanly. Always call with aggregation_level="Vault", never "Global" -- Global silently returns
  empty NFT data (see docs/posture-scanner.md). Supports batching multiple addresses in one call;
  the scanner uses this to keep the cohort scan to a handful of requests, not one per entity.
"""
import json
import subprocess

GATEWAY_URL_MAINNET = "https://mainnet.radixdlt.com"
GATEWAY_URL_STOKENET = "https://stokenet.radixdlt.com"

_CURL_TIMEOUT_SECONDS = 30


class GatewayError(Exception):
    """A Gateway call failed in a way the scanner cannot recover from on its own."""


class NotSyncedUpError(GatewayError):
    """The specific, parseable halt signal: an unpinned read refused because the Gateway's own
    database lags the ledger past its configured tolerance. Confirmed live during the halt (at the
    original scoping pass and again on a fresh re-check hours later): still the same shape,
    `{"code": 500, "details": {"type": "NotSyncedUpError", "current_sync_delay_seconds": ...,
    "max_allowed_sync_delay_seconds": ...}}`. Treat this as "confirmed still halted," not as a
    bug -- it is a stable, intentional signal from the Gateway, not noise.
    """

    def __init__(self, message, current_sync_delay_seconds=None, max_allowed_sync_delay_seconds=None):
        super().__init__(message)
        self.current_sync_delay_seconds = current_sync_delay_seconds
        self.max_allowed_sync_delay_seconds = max_allowed_sync_delay_seconds


def _post(base_url, path, body):
    """POST JSON to the Gateway via curl; return (http_status, parsed_json_or_None, raw_text)."""
    cmd = [
        "curl", "-sS",
        "-m", str(_CURL_TIMEOUT_SECONDS),
        "-X", "POST",
        "-H", "Content-Type: application/json",
        "-d", json.dumps(body),
        "-w", "\n__HTTP_STATUS__:%{http_code}",
        base_url + path,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_CURL_TIMEOUT_SECONDS + 10)
    except subprocess.TimeoutExpired as exc:
        raise GatewayError(f"curl timed out calling {path}") from exc
    except FileNotFoundError as exc:
        raise GatewayError("curl is not installed or not on PATH -- required for Gateway calls") from exc

    if proc.returncode != 0:
        raise GatewayError(f"curl exited {proc.returncode} calling {path}: {proc.stderr.strip()}")

    raw = proc.stdout
    marker = "\n__HTTP_STATUS__:"
    if marker not in raw:
        raise GatewayError(f"curl output for {path} did not carry the expected status marker: {raw[:200]!r}")
    body_text, status_text = raw.rsplit(marker, 1)
    try:
        status = int(status_text.strip())
    except ValueError as exc:
        raise GatewayError(f"could not parse HTTP status from curl output: {status_text!r}") from exc

    parsed = None
    if body_text.strip():
        try:
            parsed = json.loads(body_text)
        except json.JSONDecodeError as exc:
            raise GatewayError(f"{path} did not return valid JSON (HTTP {status}): {body_text[:200]!r}") from exc

    return status, parsed, body_text


def _raise_for_error_body(path, status, parsed):
    """Convert a non-2xx Gateway response into the right exception, parsing NotSyncedUpError
    specifically since callers branch on it. Never called for a 200.
    """
    detail_type = None
    message = f"{path} returned HTTP {status}"
    if isinstance(parsed, dict):
        message = parsed.get("message", message)
        details = parsed.get("details") or {}
        detail_type = details.get("type")
        if detail_type == "NotSyncedUpError":
            raise NotSyncedUpError(
                message,
                current_sync_delay_seconds=details.get("current_sync_delay_seconds"),
                max_allowed_sync_delay_seconds=details.get("max_allowed_sync_delay_seconds"),
            )
    raise GatewayError(f"{message} (HTTP {status}, type={detail_type})")


def gateway_status(base_url=GATEWAY_URL_MAINNET):
    """POST /status/gateway-status, unpinned. Returns the parsed body:
    {"ledger_state": {"network", "state_version", "proposer_round_timestamp", "epoch", "round"},
     "release_info": {...}}.

    This is the ONLY unpinned call the scanner makes, and it is expected to keep working during a
    halt (confirmed live: returns 200 with the frozen state_version, not a NotSyncedUpError) --
    that asymmetry (this endpoint tolerates staleness, /state/entity/details does not) is exactly
    how the scanner discovers what to pin every other read to.
    """
    status, parsed, raw = _post(base_url, "/status/gateway-status", {})
    if status != 200:
        _raise_for_error_body("/status/gateway-status", status, parsed)
    if not isinstance(parsed, dict) or "ledger_state" not in parsed:
        raise GatewayError(f"/status/gateway-status: unexpected response shape: {raw[:200]!r}")
    return parsed


def probe_halted(base_url=GATEWAY_URL_MAINNET):
    """Make one deliberately-UNPINNED /state/entity/details call against the network's own
    well-known XRD resource, purely to observe whether the Gateway is currently refusing unpinned
    reads. Returns (halted: bool, detail: str|None). Never raises -- a halt is an expected,
    parseable outcome, not a scanner failure.

    This costs one extra request per run so the report can honestly state gateway.halted rather
    than inferring it from the state_version never moving (which would be indistinguishable from
    "nothing happened to move it yet" on a live, un-halted network with a quiet week).
    """
    try:
        status, parsed, raw = _post(
            base_url, "/state/entity/details",
            {"addresses": [_WELL_KNOWN_XRD], "aggregation_level": "Vault"},
        )
    except GatewayError:
        # A network-level failure here isn't a halt signal either way -- don't guess.
        return False, None
    if status == 200:
        return False, None
    if isinstance(parsed, dict):
        details = parsed.get("details") or {}
        if details.get("type") == "NotSyncedUpError":
            return True, parsed.get("message")
    return False, None


_WELL_KNOWN_XRD = "resource_rdx1tknxxxxxxxxxradxrdxxxxxxxxx009923554798xxxxxxxxxradxrd"


def entity_details(addresses, state_version, base_url=GATEWAY_URL_MAINNET):
    """POST /state/entity/details, pinned to state_version, for one or more addresses in a
    single batched call. aggregation_level is always "Vault" (never "Global" -- see module
    docstring). Returns the parsed response body: {"ledger_state": {...}, "items": [...]}, one
    item per address, in the order the Gateway chooses to return them (NOT necessarily request
    order -- callers must index by item["address"], not by position).

    Raises NotSyncedUpError if the given state_version is far enough behind the Gateway's own
    sync tolerance to be refused -- this should not happen for a state_version obtained from a
    fresh gateway_status() call moments earlier, but a caller pinning an old/stale version on
    purpose (e.g. re-running against last week's frozen version) could hit it.
    """
    if not addresses:
        raise ValueError("entity_details requires at least one address")
    body = {
        "addresses": list(addresses),
        "aggregation_level": "Vault",
        "at_ledger_state": {"state_version": state_version},
    }
    status, parsed, raw = _post(base_url, "/state/entity/details", body)
    if status != 200:
        _raise_for_error_body("/state/entity/details", status, parsed)
    if not isinstance(parsed, dict) or "items" not in parsed:
        raise GatewayError(f"/state/entity/details: unexpected response shape: {raw[:200]!r}")
    return parsed


def entity_details_by_address(addresses, state_version, base_url=GATEWAY_URL_MAINNET):
    """Convenience wrapper over entity_details(): returns {address: item_dict}. Raises
    GatewayError if the Gateway's response is missing an address that was requested -- a
    silent gap here would otherwise surface later as a confusing KeyError deep in a check.
    """
    response = entity_details(addresses, state_version, base_url=base_url)
    by_address = {item["address"]: item for item in response.get("items", [])}
    missing = [a for a in addresses if a not in by_address]
    if missing:
        raise GatewayError(f"/state/entity/details did not return item(s) for: {missing}")
    return by_address
