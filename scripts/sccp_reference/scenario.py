"""Recording destination-model runs as fixture scenarios.

A scenario is a deployment, its initial state and a list of calls. Each
recorded step carries the call, its inputs, `now_ms`, the expected outcome
(`ok` or the §5.2.2 error name), the emitted events and the state afterwards,
which is the `(state, input, now) → (state', outcome, event)` row shape of
`specs/sccp.md` §11.1. Certificates live in a shared pool and are referenced by
id; a `SccpCertificate` event names the pooled certificate it publishes: the
one among the certificates of its own step with the `QC_FIXED`, the header and
the signature the event carries.

A step names its call as the flavor does (`CALL_NAMES`): the EVM entry point,
or the TON message of §5.3.2 (`sccp_checkpoint`, `sccp_finalize_checkpoint`, …).

`now_ms` of a step is the destination clock, `block.timestamp × 1000` (EVM) or
`now() × 1000` (TON, §0). The recorder therefore refuses a step whose `now_ms`
is not a multiple of 1000 or is earlier than the previous step's, so that an
EDR or Acton harness can replay every scenario with real block times.
"""

from __future__ import annotations

from .common import check_destination_clock
from .destination import ControlProof, Deployment, Destination, MessageProof
from .finality import Certificate, parse_header
from .taira import Committee


# The call of a step, per flavor: the EVM entry point of §5.2.2 and the TON message of §5.3.2.
CALL_NAMES = {
    "submitCheckpoints": "sccp_checkpoint",
    "finalizeFromTaira": "sccp_finalize",
    "finalizeFromCheckpoint": "sccp_finalize_checkpoint",
    "applyControl": "sccp_apply_control",
    "applyControlFromCheckpoint": "sccp_apply_control_checkpoint",
    "voidExpired": "sccp_void_expired",
    "voidExpiredFromCheckpoint": "sccp_void_expired_checkpoint",
    "voidFrozen": "sccp_void_frozen",
}


def call_name(flavor: str, evm_name: str) -> str:
    """The name a step of `flavor` records for the entry point `evm_name`."""
    return evm_name if flavor == "evm" else CALL_NAMES[evm_name]


class CertificatePool:
    """Deduplicated certificates of one fixture file."""

    def __init__(self) -> None:
        self.entries: dict[str, dict] = {}
        self._ids: dict[tuple, str] = {}

    def add(
        self,
        cert: Certificate,
        label: str,
        signed_by: str,
        *,
        next_committee: Committee | None = None,
        note: str | None = None,
    ) -> str:
        key = (cert.qc, cert.header, cert.signature_evm, cert.committee, cert.signer_ys)
        if key in self._ids:
            return self._ids[key]
        cid = f"c{len(self.entries) + 1:03d}"
        self._ids[key] = cid
        try:
            header = parse_header(cert.header).as_json()
        except Exception:  # noqa: BLE001 - dirty headers are recorded raw
            header = None
        entry = {
            "label": label,
            "signed_by": signed_by,
            "signer_indices": cert.meta["signer_indices"],
            "header_fields": header,
            "evm": cert.evm_json(),
            "ton": cert.ton_json(),
            "ton_next_keys": None if next_committee is None else next_committee.name,
        }
        if note:
            entry["note"] = note
        self.entries[cid] = entry
        return cid

    def id_of(self, qc: str, header: str, signature: str, among: list[str]) -> str | None:
        """The first certificate of `among` (the ids a step submitted) with this `QC_FIXED`, header and signature
        (in its EVM or its TON form).

        A destination publishes only a certificate of the call. Certificates of one `X` under different
        signatures are different entries, so the signature decides which of them it published.
        """
        for cid in among:
            entry = self.entries[cid]
            if (
                entry["evm"]["qc"] == qc
                and entry["evm"]["header"] == header
                and signature in (entry["evm"]["signature"], entry["ton"]["signature"])
            ):
                return cid
        return None


class Scenario:
    """One recorded scenario over a fresh `Destination`."""

    def __init__(self, name: str, description: str, deployment: Deployment, pool: CertificatePool, strict: bool = True):
        self.strict = strict
        self.name = name
        self.description = description
        self.deployment = deployment
        self.pool = pool
        self.dest = Destination(deployment)
        self.initial_state = self.dest.state.as_json()
        self.steps: list[dict] = []
        self._cert_ids: dict[int, str] = {}

    def _tick(self, call: str, now_ms: int) -> None:
        """Require a whole-second `now_ms` that does not precede the last recorded step."""
        previous = self.steps[-1]["now_ms"] if self.steps else None
        check_destination_clock(now_ms, previous, f"{self.name} step {len(self.steps)} ({call})")

    def _cert_ref(self, cert: Certificate, label: str, signed_by: str, next_committee=None) -> str:
        return self.pool.add(cert, label, signed_by, next_committee=next_committee)

    def _events(self, events: list[dict], submitted: list[str]) -> list[dict]:
        out = []
        for ev in events:
            if ev["event"] == "SccpCertificate":
                ref = self.pool.id_of(ev["qc"], ev["header"], ev["signature"], submitted)
                if ref is None:
                    raise AssertionError(f"{self.name}: a published certificate is none the step submitted")
                ev = {"event": "SccpCertificate", "height": ev["height"], "generation": ev["generation"], "certificate": ref}
            out.append(ev)
        return out

    def _record(self, call: str, inputs: dict, now_ms: int, result: dict, expect: str | None) -> dict:
        self._tick(call, now_ms)
        expected = {"outcome": result["outcome"]}
        if "error_args" in result:
            expected["error_args"] = result["error_args"]
        if "stopped" in result:
            expected["stopped"] = result["stopped"]
        if "return" in result:
            expected["return"] = result["return"]
        submitted = list(inputs.get("certificates", [])) + ([inputs["certificate"]] if "certificate" in inputs else [])
        expected["events"] = self._events(result.get("events", []), submitted)
        step = {"call": call, "now_ms": now_ms, **inputs, "expected": expected, "state_after": self.dest.state.as_json(now_ms)}
        if self.strict and expect is not None and result["outcome"] != expect:
            raise AssertionError(f"{self.name}/{call}: expected {expect}, model gave {result}")
        self.steps.append(step)
        return result

    def _call(self, evm_name: str) -> str:
        return call_name(self.deployment.flavor, evm_name)

    @staticmethod
    def _source_json(kind: str, ref) -> dict:
        return {"certificate": ref} if kind == "inline" else {"checkpoint": {"header": "0x" + ref.hex()}}

    # -- calls ---------------------------------------------------------------

    def submit(self, certs: list[tuple], now_ms: int, expect: str | None = None) -> dict:
        """`certs` is a list of `(Certificate, label, signed_by, next_committee | None)`."""
        ids = [self._cert_ref(c, label, by, nxt) for c, label, by, nxt in certs]
        next_keys = [None if nxt is None else nxt.keys for _, _, _, nxt in certs]
        result = self.dest.submit_checkpoints([c for c, *_ in certs], now_ms, next_keys)
        inputs = {"certificates": ids}
        if self.deployment.flavor == "ton":
            inputs["next_keys"] = [None if nxt is None else nxt.name for *_, nxt in certs]
        return self._record(self._call("submitCheckpoints"), inputs, now_ms, result, expect)

    def finalize(self, source: tuple, proof: MessageProof, now_ms: int, expect: str | None = None) -> dict:
        kind, value = source
        ref = self._cert_ref(*value) if kind == "inline" else value
        model_source = (kind, value[0] if kind == "inline" else value)
        result = self.dest.finalize(model_source, proof, now_ms)
        call = self._call("finalizeFromTaira" if kind == "inline" else "finalizeFromCheckpoint")
        return self._record(call, {**self._source_json(kind, ref), "proof": proof.as_json()}, now_ms, result, expect)

    def apply_control(self, source: tuple, proof: ControlProof, now_ms: int, expect: str | None = None) -> dict:
        kind, value = source
        ref = self._cert_ref(*value) if kind == "inline" else value
        model_source = (kind, value[0] if kind == "inline" else value)
        result = self.dest.apply_control(model_source, proof, now_ms)
        call = self._call("applyControl" if kind == "inline" else "applyControlFromCheckpoint")
        return self._record(call, {**self._source_json(kind, ref), "proof": proof.as_json()}, now_ms, result, expect)

    def void_expired(
        self, nonce: int, source: tuple, proof: MessageProof, now_ms: int, expect: str | None = None
    ) -> dict:
        kind, value = source
        ref = self._cert_ref(*value) if kind == "inline" else value
        model_source = (kind, value[0] if kind == "inline" else value)
        result = self.dest.void_expired(nonce, model_source, proof, now_ms)
        call = self._call("voidExpired" if kind == "inline" else "voidExpiredFromCheckpoint")
        inputs = {"nonce": nonce, **self._source_json(kind, ref), "proof": proof.as_json()}
        return self._record(call, inputs, now_ms, result, expect)

    def void_frozen(self, first: int, count: int, now_ms: int, expect: str | None = None) -> dict:
        result = self.dest.void_frozen(first, count, now_ms)
        return self._record(self._call("voidFrozen"), {"firstNonce": str(first), "count": count}, now_ms, result, expect)

    def views(self, now_ms: int) -> None:
        self._tick("views", now_ms)
        st = self.dest.state
        d = self.deployment
        self.steps.append(
            {
                "call": "views",
                "now_ms": now_ms,
                "expected": {
                    "committeeState": {
                        "root": "0x" + st.root.hex(),
                        "untilMs": st.until_ms,
                        "start": st.start,
                        "high": st.high,
                        "generation": st.generation,
                    },
                    "initialCommittee": {
                        "generation": d.pin_generation,
                        "root": "0x" + d.pin_root.hex(),
                        "start": d.pin_start_height,
                        "untilMs": d.pin_until_ms,
                    },
                    "pauseState": self.dest.pause_state(now_ms),
                    "mintingPaused": self.dest.effective_pause(now_ms),
                    "equivocated": st.equivocated,
                    "controlNonce": st.control_nonce,
                    "opCount": st.op_count,
                    "live": self.dest.live(now_ms),
                },
                "state_after": st.as_json(now_ms),
            }
        )

    def as_json(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "flavor": self.deployment.flavor,
            "deployment": self.deployment.as_json(),
            "initial_state": self.initial_state,
            "steps": self.steps,
        }
