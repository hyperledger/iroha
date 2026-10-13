"""Lightweight Torii mock server for typed Torii API smoke tests."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import signal
import socketserver
import sys
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import parse_qs, unquote, urlparse

__all__ = ["ToriiMockServer", "main"]

_CURRENT_DATA_MODEL_VERSION = 4
# Canonical Sora account controlled by the first RFC 8032 Ed25519 test key.
_MOCK_ACCOUNT_ID = "sorauﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP"


def _artifact_fixture_key(value: str) -> str:
    """Fixture keys bind one canonical full-width dataspace and artifact digest."""
    match = re.fullmatch(r"(0|[1-9][0-9]*)/([0-9a-f]{64})", value)
    if match is None or int(match[1]) >= 1 << 64 or int(match[2][-1], 16) & 1 != 1:
        raise ValueError("artifact fixture key must be canonical dataspace/code-hash")
    return value


def _default_governance_proposal_draft() -> Dict[str, Any]:
    return {
        "proposal_id": "11" * 32,
        "tx_instructions": [
            {
"wire_id": "iroha.instruction.v1::governance::ProposeDeployContract",
                "payload_hex": "00ff",
            }
        ],
    }


@dataclass
class _Response:
    status: int
    body: bytes = b""
    headers: Dict[str, str] = field(default_factory=dict)


def _canonical_hash(seed: int) -> str:
    """Return a canonical marked Iroha hash literal for mock payloads."""

    body_bytes = bytearray([seed & 0xFF] * 32)
    body_bytes[-1] |= 1
    body = body_bytes.hex().upper()
    crc = 0xFFFF
    for byte in f"hash:{body}".encode("ascii"):
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return f"hash:{body}#{crc:04X}"




class _ToriiHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, state: "_MockState"):
        super().__init__(server_address, RequestHandlerClass)
        self.mock_state = state

    def server_bind(self) -> None:
        # The mock only serves a numeric loopback address. HTTPServer's default
        # binding performs a reverse-DNS lookup that can stall isolated runners.
        socketserver.TCPServer.server_bind(self)
        server_name, self.server_port = self.server_address[:2]
        if not isinstance(server_name, str):
            raise TypeError("mock Torii requires a numeric loopback host string")
        self.server_name = server_name


class _ToriiHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:  # noqa: D401 - silence default logging
        return

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch("POST")

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        length = int(self.headers.get("Content-Length", "0")) if method in {"POST", "PUT"} else 0
        body = self.rfile.read(length) if length > 0 else b""
        try:
            response = self.server.mock_state.handle_request(  # type: ignore[attr-defined]
                method,
                parsed.path,
                params,
                body,
                self.headers,
            )
        except KeyError:
            self.send_error(HTTPStatus.NOT_FOUND, "not found")
            return
        except ValueError as err:
            self.send_error(HTTPStatus.BAD_REQUEST, str(err))
            return

        self.send_response(response.status)
        for key, value in response.headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(response.body)))
        self.end_headers()
        if response.body:
            self.wfile.write(response.body)


class _MockState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._attachment_seq = 0
        self.attachments: Dict[str, Dict[str, Any]] = {}
        self.sumeragi_status: Dict[str, Any] = {}
        self.pipeline_sequences: Dict[str, Dict[str, Any]] = {}
        self.pipeline_next_plan: Optional[Dict[str, Any]] = None
        self.pipeline_preflight: Dict[str, Any] = {}
        self.pipeline_scenario = "success"
        self._pipeline_submit_seq = 0
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.gov_referenda: Dict[str, Dict[str, Any]] = {}
        self.gov_contracts: Dict[str, Dict[str, Any]] = {}
        self.contract_manifests: Dict[str, Dict[str, Any]] = {}
        self.contract_code_bytes: Dict[str, Dict[str, Any]] = {}
        self.contract_call_response: Dict[str, Any] = {}
        self.gov_proposals: Dict[str, Dict[str, Any]] = {}
        self.gov_propose_deploy_response: Dict[str, Any] = {}
        self.gov_protected_namespaces: Dict[str, Any] = {}
        self.gov_locks: Dict[str, Dict[str, Any]] = {}
        self.gov_tallies: Dict[str, Dict[str, Any]] = {}
        self.gov_unlock_stats: Dict[str, Any] = {}
        self.reset()

    # ------------------------------------------------------------------
    # Public helpers called by server
    # ------------------------------------------------------------------
    def handle_request(
        self,
        method: str,
        path: str,
        params: Mapping[str, List[str]],
        body: bytes,
        headers: Mapping[str, str],
    ) -> _Response:
        if method == "POST" and path == "/v1/zk/attachments":
            return self._attachment_post(body, headers)
        if method == "GET" and path == "/v1/zk/attachments":
            return self._attachment_list()
        if method == "GET" and path.startswith("/v1/zk/attachments/"):
            attachment_id = path.split("/")[-1]
            return self._attachment_get(attachment_id)
        if method == "DELETE" and path.startswith("/v1/zk/attachments/"):
            attachment_id = path.split("/")[-1]
            return self._attachment_delete(attachment_id)
        if method == "POST" and path == "/v1/pipeline/transactions":
            return self._pipeline_submit(body)
        if method == "GET" and path == "/v1/pipeline/transactions/status":
            return self._pipeline_status(params)
        if method == "GET" and path == "/v1/pipeline/preflight":
            return _json_response(HTTPStatus.OK, self.pipeline_preflight)
        if method == "GET" and path.startswith("/v1/accounts/"):
            account_id = unquote(path.rsplit("/", 1)[-1])
            return self._account_get(account_id)
        if method == "POST" and path == "/v1/gov/proposals/deploy-contract":
            return self._gov_propose_deploy(body)
        if method == "POST" and path == "/v1/contracts/call":
            return self._contracts_call(body)
        if method == "POST" and path == "/v1/gov/protected-namespaces":
            return self._gov_protected_set(body)
        if method == "GET" and path == "/v1/gov/protected-namespaces":
            return self._gov_protected_get()
        if method == "GET" and path.startswith("/v1/gov/contracts/"):
            contract_address = unquote(path.rsplit("/", 1)[-1])
            return self._gov_contract_get(contract_address)
        if method == "GET" and path.startswith("/v1/gov/locks/"):
            referendum_id = path.split("/")[-1]
            return self._gov_locks_get(referendum_id)
        if method == "GET" and path.startswith("/v1/gov/referenda/"):
            referendum_id = path.split("/")[-1]
            return self._gov_referendum_get(referendum_id)
        if method == "POST" and path == "/v1/gov/ballots/plain":
            return self._gov_ballot_plain(body)
        if method == "POST" and path == "/v1/gov/ballots/zk-v1":
            return self._gov_ballot_zk_v1(body)
        if method == "GET" and path.startswith("/v1/contracts/artifacts/"):
            segments = path.split("/")
            if len(segments) == 6:
                return self._contracts_manifest_get(segments[4], segments[5])
            if len(segments) == 7 and segments[6] == "bytes":
                return self._contracts_code_bytes(segments[4], segments[5])
            return _json_response(HTTPStatus.NOT_FOUND, {"error": "unknown artifact route"})
        if method == "GET" and path.startswith("/v1/gov/tally/"):
            referendum_id = path.split("/")[-1]
            return self._gov_tally_get(referendum_id)
        if method == "GET" and path.startswith("/v1/gov/proposals/"):
            proposal_id = path.split("/")[-1]
            return self._gov_proposals_get(proposal_id)
        if method == "GET" and path == "/v1/gov/unlocks/stats":
            return self._gov_unlock_stats()
        if method == "GET" and path == "/v1/sumeragi/status":
            return _json_response(HTTPStatus.OK, self.sumeragi_status)
        if method == "GET" and path == "/v1/node/capabilities":
            return _json_response(HTTPStatus.OK, self.node_capabilities)
        if method == "POST" and path == "/__mock__/pipeline/config":
            return self._pipeline_config(body)
        if method == "POST" and path == "/__mock__/accounts/config":
            return self._account_config(body)
        if method == "POST" and path == "/__mock__/sumeragi/config":
            return self._sumeragi_config(body)
        if method == "POST" and path == "/__mock__/gov/config":
            return self._gov_config(body)
        if method == "POST" and path == "/__mock__/reset":
            self.reset()
            return _Response(HTTPStatus.OK, body=b"{}", headers={"Content-Type": "application/json"})
        raise KeyError(path)

    def reset(self) -> None:
        with self._lock:
            self.attachments.clear()
            self._attachment_seq = 0
            self.pipeline_sequences.clear()
            self.pipeline_next_plan = None
            self.pipeline_preflight = {
                "schema_version": 1,
                "chain_height": 0,
                # Torii serves only the signed-genesis target block time here; SDKs derive
                # their stall threshold from it (`PIPELINE_STALL_BLOCK_CADENCES`).
                "sumeragi": {"block_cadence_ms": 1000},
                "admission": {
                    "max_signatures": 32,
                    "max_instructions": 4096,
                    "max_tx_bytes": 1048576,
                    "max_decompressed_bytes": 1048576,
                    "max_metadata_depth": 16,
                },
                "block": {"max_transactions": 512},
                "pipeline": {
                    "signature_batch_max_ed25519": 64,
                    "signature_batch_max_secp256k1": 16,
                    "signature_batch_max_pqc": 8,
                    "signature_batch_max_bls": 16,
                    "overlay_max_instructions": 0,
                    "ivm_max_cycles_upper_bound": 2_000_000,
                    "ivm_admission_cycle_limit": 1_000_000,
                    "ivm_max_decoded_instructions": 1048576,
                },
                "queue": {"size": 0, "queued": 0, "inflight": 0},
                "fees": {
                    "fee_asset_id": "xor#sora",
                    "fee_sink_account_id": _MOCK_ACCOUNT_ID,
                    "base_fee": "0",
                    "per_byte_fee": "0",
                    "per_instruction_fee": "0",
                    "per_gas_unit_fee": "0",
                    "sponsor_vault_custody_account_id": _MOCK_ACCOUNT_ID,
                    "settlement_mode": "direct",
                    "successful_claim_fee_exempt_authorities": [],
                },
            }
            self.pipeline_scenario = "success"
            self._pipeline_submit_seq = 0
            self.accounts.clear()
            self.gov_referenda.clear()
            self.gov_contracts.clear()
            self.contract_manifests.clear()
            self.contract_code_bytes.clear()

            # Contract preparation requires an explicitly configured exact QP
            # payload fixture; a fabricated byte string is never signable.
            self.contract_call_response = {}
            self.gov_proposals.clear()
            self.gov_propose_deploy_response = _default_governance_proposal_draft()
            self.gov_protected_namespaces = {"found": False, "namespaces": []}
            self.gov_locks.clear()
            self.gov_tallies.clear()
            self.gov_unlock_stats = {
                "height_current": 0,
                "expired_locks_now": 0,
                "referenda_with_expired": 0,
                "last_sweep_height": 0,
            }
            self.node_capabilities = {
                "abi_version": 1,
                "data_model_version": _CURRENT_DATA_MODEL_VERSION,
                "signed_transaction_schema_hash_hex": "7ab5ff9c572efb316deac478f19209c5",
            }
            self._seed_sumeragi()

    # ------------------------------------------------------------------
    # Governance endpoints
    # ------------------------------------------------------------------
    def _gov_config(self, body: bytes) -> _Response:
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except json.JSONDecodeError as err:
            raise ValueError(f"invalid governance config: {err}") from err
        referenda = payload.get("referenda", [])
        if not isinstance(referenda, list):
            raise ValueError("referenda must be a list")
        new_state: Dict[str, Dict[str, Any]] = {}
        for entry in referenda:
            if not isinstance(entry, dict):
                raise ValueError("referendum entry must be an object")
            referendum_data = entry.get("referendum") or {}
            if not isinstance(referendum_data, dict):
                raise ValueError("referendum field must be an object")
            referendum_id = entry.get("id") or referendum_data.get("id")
            if not referendum_id or not isinstance(referendum_id, str):
                raise ValueError("referendum entry missing id")
            referendum_payload = dict(referendum_data)
            referendum_payload.setdefault("id", referendum_id)
            mode_value = referendum_payload.get("mode")
            if not isinstance(mode_value, str):
                raise ValueError("referendum.mode must be a string")
            new_state[referendum_id] = {
                "referendum": referendum_payload,
                "ballot_plain": entry.get("ballot_plain_response"),
                "ballot_zk_v1": entry.get("ballot_zk_response"),
                "ballot_plain_request": entry.get("ballot_plain_request"),
                "ballot_zk_request": entry.get("ballot_zk_request"),
            }
        self.gov_referenda = new_state

        gov_contracts_payload = payload.get("gov_contracts")
        if gov_contracts_payload is not None:
            if not isinstance(gov_contracts_payload, dict):
                raise ValueError("gov_contracts must be an object")
            normalized_contracts: Dict[str, Dict[str, Any]] = {}
            for contract_address, entry in gov_contracts_payload.items():
                if not isinstance(entry, dict):
                    raise ValueError("gov_contracts entry must be an object")
                normalized_contracts[str(contract_address)] = entry
            self.gov_contracts = normalized_contracts
        else:
            self.gov_contracts = {}

        manifests_payload = payload.get("manifests")
        if manifests_payload is not None:
            if not isinstance(manifests_payload, dict):
                raise ValueError("manifests must be an object")
            normalized_manifests: Dict[str, Dict[str, Any]] = {}
            for key, value in manifests_payload.items():
                if not isinstance(value, dict):
                    raise ValueError("manifest entry must be an object")
                normalized_manifests[_artifact_fixture_key(str(key))] = value
            self.contract_manifests = normalized_manifests
        else:
            self.contract_manifests = {}

        code_bytes_payload = payload.get("code_bytes")
        if code_bytes_payload is not None:
            if not isinstance(code_bytes_payload, dict):
                raise ValueError("code_bytes must be an object")
            normalized_code_bytes: Dict[str, Dict[str, Any]] = {}
            for key, value in code_bytes_payload.items():
                if not isinstance(value, dict):
                    raise ValueError("code_bytes entry must be an object")
                normalized_code_bytes[_artifact_fixture_key(str(key))] = value
            self.contract_code_bytes = normalized_code_bytes
        else:
            self.contract_code_bytes = {}

        contract_call_payload = payload.get("contract_call_response")
        if contract_call_payload is not None:
            if not isinstance(contract_call_payload, dict):
                raise ValueError("contract_call_response must be an object")
            self.contract_call_response = dict(contract_call_payload)

        proposals_payload = payload.get("proposals")
        if proposals_payload is not None:
            if not isinstance(proposals_payload, dict):
                raise ValueError("proposals must be an object")
            normalized_proposals: Dict[str, Dict[str, Any]] = {}
            for key, value in proposals_payload.items():
                if not isinstance(value, dict):
                    raise ValueError("proposal entry must be an object")
                normalized_proposals[str(key).lower()] = value
            self.gov_proposals = normalized_proposals
        else:
            self.gov_proposals = {}

        propose_payload = payload.get("propose_deploy_response")
        if propose_payload is not None:
            if not isinstance(propose_payload, dict):
                raise ValueError("propose_deploy_response must be an object")
            self.gov_propose_deploy_response = dict(propose_payload)
        else:
            self.gov_propose_deploy_response = _default_governance_proposal_draft()

        protected_payload = payload.get("protected_namespaces")
        if protected_payload is not None:
            if not isinstance(protected_payload, dict):
                raise ValueError("protected_namespaces must be an object")
            namespaces_value = protected_payload.get("namespaces", [])
            if namespaces_value is None:
                namespaces_list: List[str] = []
            else:
                if not isinstance(namespaces_value, list):
                    raise ValueError("protected_namespaces.namespaces must be a list")
                namespaces_list = []
                for raw in namespaces_value:
                    if not isinstance(raw, str):
                        raise ValueError("protected_namespaces entries must be strings")
                    namespaces_list.append(raw)
            found_value = protected_payload.get("found")
            if found_value is None:
                found = bool(namespaces_list)
            elif isinstance(found_value, bool):
                found = found_value
            else:
                raise ValueError("protected_namespaces.found must be a boolean")
            self.gov_protected_namespaces = {
                "found": found,
                "namespaces": namespaces_list,
            }
        else:
            self.gov_protected_namespaces = {"found": False, "namespaces": []}

        locks_payload = payload.get("locks")
        if locks_payload is not None:
            if not isinstance(locks_payload, dict):
                raise ValueError("locks must be an object")
            normalized_locks: Dict[str, Dict[str, Any]] = {}
            for key, value in locks_payload.items():
                if not isinstance(value, dict):
                    raise ValueError("locks entry must be an object")
                normalized_locks[str(key)] = value
            self.gov_locks = normalized_locks
        else:
            self.gov_locks = {}

        tallies_payload = payload.get("tallies")
        if tallies_payload is not None:
            if not isinstance(tallies_payload, dict):
                raise ValueError("tallies must be an object")
            normalized_tallies: Dict[str, Dict[str, Any]] = {}
            for key, value in tallies_payload.items():
                if not isinstance(value, dict):
                    raise ValueError("tally entry must be an object")
                normalized_tallies[str(key)] = value
            self.gov_tallies = normalized_tallies
        else:
            self.gov_tallies = {}

        unlock_payload = payload.get("unlock_stats")
        if unlock_payload is not None:
            if not isinstance(unlock_payload, dict):
                raise ValueError("unlock_stats must be an object")
            def _expect_int(name: str) -> int:
                value = unlock_payload.get(name, 0)
                if isinstance(value, bool):
                    return int(value)
                if isinstance(value, (int, float)):
                    return int(value)
                if isinstance(value, str):
                    value_str = value.strip()
                    if value_str == "":
                        return 0
                    return int(value_str)
                raise ValueError(f"unlock_stats.{name} must be an integer")
            self.gov_unlock_stats = {
                "height_current": _expect_int("height_current"),
                "expired_locks_now": _expect_int("expired_locks_now"),
                "referenda_with_expired": _expect_int("referenda_with_expired"),
                "last_sweep_height": _expect_int("last_sweep_height"),
            }
        else:
            self.gov_unlock_stats = {
                "height_current": 0,
                "expired_locks_now": 0,
                "referenda_with_expired": 0,
                "last_sweep_height": 0,
            }

        return _json_response(HTTPStatus.OK, {"configured": len(new_state)})

    def _gov_propose_deploy(self, body: bytes) -> _Response:
        if body:
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except json.JSONDecodeError as err:
                raise ValueError(f"invalid propose-deploy payload: {err}") from err
            if not isinstance(payload, dict):
                raise ValueError("propose-deploy payload must be an object")
            if ("contract_address" in payload) == ("contract_alias" in payload):
                raise ValueError("propose-deploy payload must include exactly one of contract_address or contract_alias")
            allowed_fields = {
                "proposal_operator",
                "contract_address",
                "contract_alias",
                "abi_version",
                "code_hash",
                "abi_hash",
                "manifest_provenance",
            }
            unknown_fields = sorted(set(payload).difference(allowed_fields))
            if unknown_fields:
                raise ValueError(
                    f"propose-deploy payload contains unknown field '{unknown_fields[0]}'"
                )
            if payload.get("proposal_operator") is None:
                raise ValueError("propose-deploy proposal_operator is required")
            _ensure_governance_owner_canonical(
                payload["proposal_operator"], context="propose-deploy proposal_operator"
            )
            if payload.get("abi_version") != 1 or isinstance(payload.get("abi_version"), bool):
                raise ValueError("propose-deploy abi_version must be the integer 1")
            for key in ("code_hash", "abi_hash"):
                value = payload.get(key)
                if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                    raise ValueError(
                        f"propose-deploy payload '{key}' must be 32 lowercase hexadecimal bytes"
                    )
            provenance = payload.get("manifest_provenance")
            if provenance is not None:
                if not isinstance(provenance, dict) or set(provenance) != {
                    "signer",
                    "signature",
                }:
                    raise ValueError(
                        "propose-deploy manifest_provenance must contain exactly signer and signature"
                    )
        response = json.loads(json.dumps(self.gov_propose_deploy_response))
        return _json_response(HTTPStatus.OK, response)

    def _gov_protected_set(self, body: bytes) -> _Response:
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except json.JSONDecodeError as err:
            raise ValueError(f"invalid protected-namespaces payload: {err}") from err
        if not isinstance(payload, dict):
            raise ValueError("protected-namespaces payload must be an object")
        namespaces = payload.get("namespaces")
        if not isinstance(namespaces, list):
            raise ValueError("namespaces must be a list")
        trimmed: List[str] = []
        for entry in namespaces:
            if not isinstance(entry, str):
                raise ValueError("namespaces must contain strings")
            name = entry.strip()
            if name:
                trimmed.append(name)
        with self._lock:
            self.gov_protected_namespaces = {"found": True, "namespaces": list(trimmed)}
        return _json_response(HTTPStatus.OK, {"ok": True, "applied": len(trimmed)})

    def _gov_protected_get(self) -> _Response:
        with self._lock:
            payload = dict(self.gov_protected_namespaces)
        namespaces_value = payload.get("namespaces")
        if isinstance(namespaces_value, list):
            payload["namespaces"] = list(namespaces_value)
        else:
            payload["namespaces"] = []
        payload.setdefault("found", False)
        return _json_response(HTTPStatus.OK, payload)

    def _gov_locks_get(self, referendum_id: str) -> _Response:
        with self._lock:
            entry = self.gov_locks.get(referendum_id)
        if entry is None:
            payload: Dict[str, Any] = {
                "found": False,
                "referendum_id": referendum_id,
            }
        else:
            payload = dict(entry)
            payload.setdefault("referendum_id", referendum_id)
            payload.setdefault("found", True)
        return _json_response(HTTPStatus.OK, payload)

    def _gov_tally_get(self, referendum_id: str) -> _Response:
        with self._lock:
            entry = self.gov_tallies.get(referendum_id)
        if entry is None:
            payload: Dict[str, Any] = {
                "referendum_id": referendum_id,
                "approve": 0,
                "reject": 0,
                "abstain": 0,
            }
        else:
            payload = dict(entry)
            payload.setdefault("referendum_id", referendum_id)
            payload.setdefault("approve", 0)
            payload.setdefault("reject", 0)
            payload.setdefault("abstain", 0)
        return _json_response(HTTPStatus.OK, payload)

    def _gov_unlock_stats(self) -> _Response:
        with self._lock:
            payload = dict(self.gov_unlock_stats)
        payload.setdefault("height_current", 0)
        payload.setdefault("expired_locks_now", 0)
        payload.setdefault("referenda_with_expired", 0)
        payload.setdefault("last_sweep_height", 0)
        return _json_response(HTTPStatus.OK, payload)

    def _gov_referendum_get(self, referendum_id: str) -> _Response:
        entry = self.gov_referenda.get(referendum_id)
        if entry is None:
            return _json_response(HTTPStatus.OK, {"found": False})
        return _json_response(
            HTTPStatus.OK,
            {"found": True, "referendum": dict(entry["referendum"])},
        )

    def _gov_ballot_plain(self, body: bytes) -> _Response:
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except json.JSONDecodeError as err:
            raise ValueError(f"invalid plain ballot payload: {err}") from err
        referendum_id = payload.get("referendum_id")
        if not isinstance(referendum_id, str):
            raise ValueError("referendum_id must be provided")
        entry = self.gov_referenda.get(referendum_id)
        if entry is None or entry.get("ballot_plain") is None:
            raise KeyError("governance plain ballot not configured")
        expected = entry.get("ballot_plain_request")
        if expected is not None and payload != expected:
            raise ValueError("plain ballot differs from the exact configured request")
        return _json_response(HTTPStatus.OK, entry["ballot_plain"])

    def _gov_ballot_zk_v1(self, body: bytes) -> _Response:
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except json.JSONDecodeError as err:
            raise ValueError(f"invalid zk-v1 ballot payload: {err}") from err
        if not isinstance(payload, dict):
            raise ValueError("zk-v1 ballot payload must be an object")
        supported_fields = {
            "authority",
            "network_id",
            "election_id",
            "backend",
            "envelope_b64",
            "root_hint",
            "owner",
            "amount",
            "duration_blocks",
            "direction",
            "nullifier",
        }
        unknown = sorted(set(payload).difference(supported_fields))
        if unknown:
            raise ValueError(f"zk-v1 ballot payload contains unknown field {unknown[0]!r}")
        for field_name in ("authority", "network_id", "election_id", "backend"):
            value = payload.get(field_name)
            if (
                not isinstance(value, str)
                or not value
                or value != value.strip()
                or any(char.isspace() for char in value)
            ):
                raise ValueError(
                    f"zk-v1 ballot payload.{field_name} must be an exact token"
                )
        envelope_b64 = payload.get("envelope_b64")
        if not isinstance(envelope_b64, str) or not envelope_b64:
            raise ValueError("zk-v1 ballot payload.envelope_b64 must be non-empty base64")
        try:
            envelope = base64.b64decode(envelope_b64, validate=True)
        except (ValueError, binascii.Error) as err:
            raise ValueError("zk-v1 ballot payload.envelope_b64 must be valid base64") from err
        if not envelope or base64.b64encode(envelope).decode("ascii") != envelope_b64:
            raise ValueError("zk-v1 ballot payload.envelope_b64 must be canonical base64")
        election_id = payload.get("election_id")
        if not isinstance(election_id, str):
            raise ValueError("zk-v1 ballot payload.election_id must be an exact token")
        has_owner = payload.get("owner") is not None
        has_amount = payload.get("amount") is not None
        has_duration = payload.get("duration_blocks") is not None
        if (has_owner or has_amount or has_duration) and not (
            has_owner and has_amount and has_duration
        ):
            raise ValueError(
                "zk-v1 lock hints must include owner, amount, duration_blocks"
            )
        _ensure_governance_owner_canonical(
            payload.get("owner"),
            context="zk-v1 ballot",
        )
        entry = self.gov_referenda.get(election_id)
        if entry is None or entry.get("ballot_zk_v1") is None:
            raise KeyError("governance zk-v1 ballot not configured")
        expected = entry.get("ballot_zk_request")
        if expected is not None and payload != expected:
            raise ValueError("zk-v1 ballot differs from the exact configured request")
        return _json_response(HTTPStatus.OK, entry["ballot_zk_v1"])

    def _gov_contract_get(self, contract_address: str) -> _Response:
        entry = self.gov_contracts.get(contract_address)
        if entry is None:
            return _json_response(
                HTTPStatus.OK,
                {
                    "found": False,
                    "contract_address": contract_address,
                    "dataspace": "universal",
                },
            )
        payload = dict(entry)
        payload.setdefault("found", True)
        payload.setdefault("contract_address", contract_address)
        return _json_response(HTTPStatus.OK, payload)

    def _contracts_manifest_get(self, dataspace: str, code_hash: str) -> _Response:
        try:
            key = _artifact_fixture_key(f"{dataspace}/{code_hash}")
        except ValueError:
            return _json_response(HTTPStatus.BAD_REQUEST, {"error": "invalid artifact identity"})
        payload = self.contract_manifests.get(key)
        if payload is None:
            return _json_response(HTTPStatus.NOT_FOUND, {"error": "manifest not found"})
        return _json_response(HTTPStatus.OK, payload)

    def _contracts_code_bytes(self, dataspace: str, code_hash: str) -> _Response:
        try:
            key = _artifact_fixture_key(f"{dataspace}/{code_hash}")
        except ValueError:
            return _json_response(HTTPStatus.BAD_REQUEST, {"error": "invalid artifact identity"})
        payload = self.contract_code_bytes.get(key)
        if payload is None:
            return _json_response(HTTPStatus.NOT_FOUND, {"error": "code bytes not found"})
        return _json_response(HTTPStatus.OK, payload)


    def _contracts_call(self, body: bytes) -> _Response:
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except json.JSONDecodeError as err:
            raise ValueError(f"invalid contract call payload: {err}") from err
        if not isinstance(payload, dict):
            raise ValueError("contract call payload must be an object")
        if "private_key" in payload:
            raise ValueError("contract call payload must not contain private_key")
        for key in ("authority", "entrypoint"):
            value = payload.get(key)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"contract call payload missing '{key}'")
        if ("contract_address" in payload) == ("contract_alias" in payload):
            raise ValueError("contract call payload must include exactly one of contract_address or contract_alias")
        fee_payment = payload.get("fee_payment")
        if not isinstance(fee_payment, dict) or not isinstance(fee_payment.get("value"), dict):
            raise ValueError("contract call payload missing 'fee_payment'")
        gas_limit = fee_payment["value"].get("gas_limit")
        if not isinstance(gas_limit, int) or isinstance(gas_limit, bool) or gas_limit <= 0:
            raise ValueError("contract call fee_payment missing positive 'gas_limit'")
        if not self.contract_call_response:
            return _json_response(HTTPStatus.SERVICE_UNAVAILABLE, {
                "error": "an exact canonical contract draft fixture is required",
            })
        response = dict(self.contract_call_response)
        tx_hash_hex = None
        response.setdefault(
            "operation_receipt",
            {
                "operation_kind": "contract_call",
                "status": "pending_signature",
                "transport": "torii",
                "dataspace": response.get("dataspace", "universal"),
                "contract_alias": payload.get("contract_alias"),
                "contract_address": response.get("contract_address"),
                "code_hash_hex": response.get("code_hash_hex"),
                "abi_hash_hex": response.get("abi_hash_hex"),
                "tx_hash_hex": tx_hash_hex,
                "entrypoint": payload["entrypoint"],
                "entrypoint_hash_hex": response.get("entrypoint_hash_hex"),
                "gas_limit": gas_limit,
                "gas_used": None,
                "fee_payment": fee_payment,
                "payload_digest_hex": "00" * 32,
            },
        )
        return _json_response(HTTPStatus.OK, response)

    def _gov_proposals_get(self, proposal_id: str) -> _Response:
        key = proposal_id.lower()
        payload = self.gov_proposals.get(key)
        if payload is None:
            return _json_response(HTTPStatus.OK, {"found": False})
        return _json_response(HTTPStatus.OK, payload)

    # ------------------------------------------------------------------
    # Pipeline endpoints
    # ------------------------------------------------------------------
    def _pipeline_submit(self, body: bytes) -> _Response:  # noqa: ARG002 - future body inspection
        plan = self._make_pipeline_plan()
        statuses = [dict(entry) for entry in plan["statuses"]]
        with self._lock:
            hash_value = plan["hash"] or self._next_pipeline_hash_locked()
            sequence = {
                "remaining": statuses,
                "repeat_last": plan["repeat_last"],
                "last": None,
            }
            self.pipeline_sequences[hash_value] = sequence
        response_body = {
            "payload": {
                "entrypoint_hash": hash_value,
                "signed_transaction_hash": None,
                "submitted_at_ms": 0,
                "submitted_at_height": 0,
                "signer": "mock-signer",
            },
            "signature": "mock-signature",
        }
        return _json_response(plan["submit_status"], response_body)

    def _pipeline_status(self, params: Mapping[str, List[str]]) -> _Response:
        hashes = params.get("hash")
        if not hashes:
            raise ValueError("missing hash query parameter")
        hash_value = str(hashes[0])
        scope = params.get("scope", ["global"])[0]
        if scope not in {"local", "global"}:
            raise ValueError("scope must be local or global")
        with self._lock:
            sequence = self.pipeline_sequences.get(hash_value)
            if sequence is None:
                # Absence is a typed observation bound to the exact lookup, as in Torii.
                return _json_response(HTTPStatus.NOT_FOUND, {
                    "code": "pipeline_transaction_status_not_found",
                    "message": "No transaction status is available for the exact requested hash and scope.",
                    "details": {
                        "pipeline_transaction_status_not_found": {
                            "hash": hash_value,
                            "scope": scope,
                        },
                    },
                })
            remaining = sequence["remaining"]
            if remaining:
                current = dict(remaining.pop(0))
                sequence["last"] = current
            else:
                current = dict(sequence.get("last") or {"kind": "Queued"})
                sequence["last"] = current
                if not sequence["repeat_last"]:
                    self.pipeline_sequences.pop(hash_value, None)
        payload = self._make_status_payload(hash_value, current)
        return _json_response(HTTPStatus.OK, payload)

    def _pipeline_config(self, body: bytes) -> _Response:
        if body:
            try:
                raw = json.loads(body.decode("utf-8"))
            except json.JSONDecodeError as err:  # pragma: no cover - defensive
                raise ValueError(f"invalid JSON: {err}") from err
            if not isinstance(raw, dict):
                raise ValueError("pipeline config must be a JSON object")
            payload: Dict[str, Any] = raw
        else:
            payload = {}

        supported_fields = {"scenario", "hash", "statuses", "repeat_last", "submit_status"}
        unsupported_fields = sorted(set(payload) - supported_fields)
        if unsupported_fields:
            raise ValueError(
                f"pipeline config contains unsupported fields: {', '.join(unsupported_fields)}"
            )

        scenario_value = payload.get("scenario")
        if scenario_value is not None:
            scenario_str = str(scenario_value)
            if scenario_str not in {"success", "failure", "timeout"}:
                raise ValueError("invalid pipeline scenario")
            with self._lock:
                self.pipeline_scenario = scenario_str

        statuses_override = None
        if "statuses" in payload:
            statuses_value = payload["statuses"]
            if not isinstance(statuses_value, list):
                raise ValueError("statuses must be a list")
            statuses_override = [self._normalize_status_entry(item) for item in statuses_value]

        overrides: Dict[str, Any] = {
            "hash": payload.get("hash"),
            "submit_status": payload.get("submit_status"),
            "repeat_last": payload.get("repeat_last"),
            "statuses": statuses_override,
        }
        if scenario_value is not None:
            overrides["scenario"] = scenario_value

        with self._lock:
            self.pipeline_next_plan = overrides
            if (
                isinstance(overrides.get("hash"), str)
                and overrides["hash"]
                and statuses_override is not None
            ):
                self.pipeline_sequences[overrides["hash"]] = {
                    "remaining": [dict(entry) for entry in statuses_override],
                    "repeat_last": bool(payload.get("repeat_last", True)),
                    "last": None,
                }

        return _json_response(HTTPStatus.OK, {"configured": True, "scenario": self.pipeline_scenario})

    def _account_config(self, body: bytes) -> _Response:
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except json.JSONDecodeError as err:
            raise ValueError(f"invalid account config: {err}") from err
        if not isinstance(payload, dict):
            raise ValueError("account config must be a JSON object")
        entries = payload.get("accounts", [])
        if not isinstance(entries, list):
            raise ValueError("accounts must be a list")

        configured: Dict[str, Dict[str, Any]] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("account entry must be an object")
            account_id = entry.get("account_id")
            if not isinstance(account_id, str) or not account_id:
                raise ValueError("account entry missing account_id")
            configured[account_id] = json.loads(json.dumps(entry))

        with self._lock:
            self.accounts = configured

        return _json_response(HTTPStatus.OK, {"configured": len(configured)})

    def _account_get(self, account_id: str) -> _Response:
        with self._lock:
            payload = self.accounts.get(account_id)
            if payload is None:
                raise KeyError("account read")
            response = json.loads(json.dumps(payload))
        return _json_response(HTTPStatus.OK, response)

    def _make_pipeline_plan(self) -> Dict[str, Any]:
        with self._lock:
            overrides = self.pipeline_next_plan
            self.pipeline_next_plan = None
            scenario = self.pipeline_scenario
            if overrides and overrides.get("scenario") is not None:
                scenario = str(overrides["scenario"])

        base = self._scenario_plan(scenario)
        hash_override = overrides.get("hash") if overrides else None
        if hash_override in ("", None):
            hash_value = None
        elif isinstance(hash_override, str):
            hash_value = hash_override
        else:
            hash_value = str(hash_override)

        submit_status = overrides.get("submit_status") if overrides and overrides.get("submit_status") is not None else base["submit_status"]
        repeat_last = overrides.get("repeat_last") if overrides and overrides.get("repeat_last") is not None else base["repeat_last"]
        statuses_source = overrides.get("statuses") if overrides and overrides.get("statuses") is not None else base["statuses"]

        if statuses_source is None:
            statuses_source = []
        submit_status_value = submit_status if submit_status is not None else HTTPStatus.ACCEPTED
        statuses = [self._normalize_status_entry(entry) for entry in statuses_source]
        plan = {
            "hash": hash_value,
            "submit_status": int(submit_status_value),
            "repeat_last": bool(repeat_last),
            "statuses": statuses,
        }
        return plan

    def _scenario_plan(self, scenario: Optional[str]) -> Dict[str, Any]:
        if scenario == "failure":
            statuses: List[Dict[str, Any]] = [
                {"kind": "Queued"},
                {"kind": "Rejected"},
            ]
        elif scenario == "timeout":
            statuses = [{"kind": "Queued"}]
        else:
            statuses = [
                {"kind": "Queued"},
                {"kind": "Approved"},
                {"kind": "Committed"},
            ]
        return {
            "hash": None,
            "submit_status": HTTPStatus.ACCEPTED,
            "repeat_last": True,
            "statuses": statuses,
        }

    @staticmethod
    def _normalize_status_entry(entry: object) -> Dict[str, Any]:
        if isinstance(entry, str):
            entry = {"kind": entry}
        if isinstance(entry, Mapping):
            unsupported = sorted(
                set(entry) - {"kind", "block_height", "scope", "resolved_from"}
            )
            if unsupported:
                raise ValueError(
                    f"status entry contains unsupported fields: {', '.join(unsupported)}"
                )
            if "kind" not in entry:
                raise ValueError("status entry missing 'kind'")
            kind = str(entry["kind"])
            if kind not in {"Queued", "Approved", "Committed", "Applied", "Rejected", "Expired"}:
                raise ValueError("unsupported pipeline status kind")
            block_height = entry.get("block_height")
            if block_height is not None and (
                type(block_height) is not int or block_height <= 0
            ):
                raise ValueError("status block_height must be a positive integer")
            scope = entry.get("scope")
            if scope is not None and scope not in {"local", "auto", "global"}:
                raise ValueError("unsupported pipeline status scope")
            resolved_from = entry.get("resolved_from")
            if resolved_from is not None and resolved_from not in {"queue", "cache", "state"}:
                raise ValueError("unsupported pipeline status provenance")
            normalized: Dict[str, Any] = {"kind": kind}
            if block_height is not None:
                normalized["block_height"] = block_height
            if scope is not None:
                normalized["scope"] = scope
            if resolved_from is not None:
                normalized["resolved_from"] = resolved_from
            return normalized
        raise ValueError("invalid status entry")

    @staticmethod
    def _make_status_payload(hash_value: str, entry: Mapping[str, Any]) -> Dict[str, Any]:
        kind = str(entry.get("kind", "Queued"))
        block_height = entry.get("block_height")
        if block_height is None and kind == "Applied":
            block_height = 1
        status: Dict[str, Any] = {"kind": kind}
        if block_height is not None:
            status["block_height"] = block_height
        scope = entry.get("scope")
        if scope is None:
            scope = "global"
        resolved_from = entry.get("resolved_from")
        if resolved_from is None:
            resolved_from = (
                "queue"
                if kind == "Queued"
                else "cache"
                if kind in {"Approved", "Committed"}
                else "state"
            )
        return {
            "hash": hash_value,
            "status": status,
            "scope": str(scope),
            "resolved_from": str(resolved_from),
        }

    def _next_pipeline_hash_locked(self) -> str:
        self._pipeline_submit_seq += 1
        return f"{self._pipeline_submit_seq:064x}"

    # ------------------------------------------------------------------
    # Attachments
    # ------------------------------------------------------------------
    def _attachment_post(self, body: bytes, headers: Mapping[str, str]) -> _Response:
        content_type = headers.get("Content-Type", "application/octet-stream")
        meta = self._register_attachment(body, content_type)
        return _json_response(HTTPStatus.CREATED, meta)

    def _attachment_list(self) -> _Response:
        with self._lock:
            items = [self._attachment_meta(rec) for rec in self.attachments.values()]
        items.sort(key=lambda item: item.get("created_ms", 0))
        return _json_response(HTTPStatus.OK, items)

    def _attachment_get(self, attachment_id: str) -> _Response:
        with self._lock:
            record = self.attachments.get(attachment_id)
            if record is None:
                raise KeyError("attachment")
            body_value = record.get("bytes")
            if not isinstance(body_value, (bytes, bytearray)):
                raise KeyError("attachment bytes")
            body = bytes(body_value)
            ct = str(record.get("content_type", "application/octet-stream"))
        return _Response(HTTPStatus.OK, body=body, headers={"Content-Type": ct})

    def _attachment_delete(self, attachment_id: str) -> _Response:
        with self._lock:
            if attachment_id not in self.attachments:
                raise KeyError("attachment")
            del self.attachments[attachment_id]
        return _Response(HTTPStatus.NO_CONTENT)

    def _register_attachment(self, body: bytes, content_type: str) -> Dict[str, Any]:
        with self._lock:
            self._attachment_seq += 1
            attachment_id = f"att-{self._attachment_seq:04d}"
            created_ms = self._timestamp_ms(self._attachment_seq)
            record: Dict[str, Any] = {
                "id": attachment_id,
                "content_type": content_type,
                "size": len(body),
                "created_ms": created_ms,
                "bytes": body,
            }
            self.attachments[attachment_id] = record
            return self._attachment_meta(record)

    @staticmethod
    def _attachment_meta(record: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            "id": record.get("id", ""),
            "content_type": record.get("content_type", "application/octet-stream"),
            "size": record.get("size", 0),
            "created_ms": record.get("created_ms", 0),
        }

    @staticmethod
    def _timestamp_ms(seq: int) -> int:
        return int(time.time() * 1000) + seq

    def _seed_sumeragi(self) -> None:
        # Observation fixture only; this is not generated finality authority.
        self.sumeragi_status = {'protocol_version': 1, 'config_fingerprint': 'hash:0101010101010101010101010101010101010101010101010101010101010101#B86C', 'beacon_horizon': None, 'instance': '0000000000000000000000000000000000000000000000000000000000000000', 'height': 10, 'view': 2, 'stage': 0, 'leader': None, 'proxy_tail': None, 'high_qc_view': None, 'level': 0, 'start_level': 0, 't_retx_ms': 1, 'committed_height': 9, 'applied_height': 9, 'awaiting': False, 'signer': None, 'unanchored': True, 'abstaining': True, 'halted': None, 'footprint': {'votes': 0, 'timeouts': 0, 'blocks': 0, 'exec_entries': 0, 'wants': 0, 'pending_apply': 0, 'sync_entries': 0, 'sync_bytes': 0, 'peers': 0, 'recent_headers': 0, 'configs': 0, 'cert_cache': 0, 'evidence_keys': 0, 'probe': 0}}

    def _sumeragi_config(self, body: bytes) -> _Response:
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except json.JSONDecodeError as err:
            raise ValueError(f"invalid sumeragi config: {err}") from err
        if not isinstance(payload, dict):
            raise ValueError("sumeragi config must be an object")

        allowed_fields = {"status"}
        unknown_fields = set(payload) - allowed_fields
        if unknown_fields:
            raise ValueError(
                f"sumeragi config contains unknown field {sorted(unknown_fields)[0]}"
            )

        updates: Dict[str, Dict[str, Any]] = {}
        for name, attribute in (
            ("status", "sumeragi_status"),
        ):
            value = payload.get(name)
            if value is not None:
                if not isinstance(value, dict):
                    raise ValueError(f"{name} must be an object")
                updates[attribute] = dict(value)

        with self._lock:
            for attribute, value in updates.items():
                setattr(self, attribute, value)

        return _json_response(HTTPStatus.OK, {"ok": True})


def _json_response(status: int, payload: object) -> _Response:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return _Response(status, body=body, headers={"Content-Type": "application/json"})


def _ensure_governance_owner_canonical(owner: Any, *, context: str) -> None:
    if owner is None:
        return
    if not isinstance(owner, str):
        raise ValueError(f"{context}.owner must be a canonical I105 account id")
    trimmed = owner.strip()
    if not trimmed or trimmed != owner:
        raise ValueError(f"{context}.owner must be a canonical I105 account id")
    if any(ch.isspace() for ch in trimmed):
        raise ValueError(f"{context}.owner must be a canonical I105 account id")
    if "@" in trimmed:
        raise ValueError(f"{context}.owner must be a canonical I105 account id")
    if trimmed.lower().startswith("0x"):
        raise ValueError(f"{context}.owner must be a canonical I105 account id")


class ToriiMockServer:
    """Embedded HTTP server used by tests in multiple languages."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._state = _MockState()
        self._server = _ToriiHTTPServer((host, port), _ToriiHandler, self._state)
        self._thread: Optional[threading.Thread] = None

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        host_value = host.decode("utf-8") if isinstance(host, (bytes, bytearray)) else host
        return f"http://{host_value}:{port}/"

    def start(self) -> "ToriiMockServer":
        if self._thread is None:
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None
        self._server.server_close()

    def reset(self) -> None:
        self._state.reset()

    def serve_forever(self) -> None:
        try:
            self._server.serve_forever()
        finally:
            self._server.server_close()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Torii mock server")
    parser.add_argument("--host", default="127.0.0.1", help="Listen host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=0, help="Listen port (default: auto)")
    parser.add_argument(
        "--stdio",
        action="store_true",
        help="Emit base URL as JSON to stdout and wait for termination",
    )
    args = parser.parse_args(argv)

    server = ToriiMockServer(args.host, args.port)

    def _graceful_shutdown(signum, frame):  # noqa: D401 - simple signal handler
        _ = (signum, frame)
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _graceful_shutdown)
    signal.signal(signal.SIGINT, _graceful_shutdown)

    if args.stdio:
        server.start()
        print(json.dumps({"base_url": server.base_url}), flush=True)
        try:
            # The background thread owns the server loop; running a second
            # loop here can deadlock signal-driven shutdown on test teardown.
            threading.Event().wait()
        except SystemExit:
            raise
        except Exception:  # pragma: no cover - unexpected runtime failure
            server.stop()
            raise
        return 0

    print(f"Torii mock server listening on {server.base_url}")
    try:
        server.serve_forever()
    except SystemExit:
        raise
    except Exception:  # pragma: no cover - unexpected runtime failure
        server.stop()
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main())
