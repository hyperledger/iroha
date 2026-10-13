from __future__ import annotations

import base64
import subprocess
from urllib.parse import quote

import iroha_native._loader as native_loader
import pytest

import iroha_python.connect as connect

_STALE_LIBPYTHON_PATH = (
    "target/kotodama-v1-uv-python/cpython-3.12.11-macos-aarch64-none/"
    "lib/libpython3.12.dylib"
)


class FakeToriiConnectClient:
    def __init__(self, *, response: object | None = None) -> None:
        self.calls: list[dict[str, object]] = []
        self.response = response

    def create_connect_session(self, payload: dict[str, object]) -> object:
        self.calls.append(dict(payload))
        if self.response is not None:
            return self.response
        sid = str(payload["sid"])
        network_id = connect.NetworkId.parse(str(payload["network_id"]))
        app_pk = str(payload["app_pk"])
        nonce = str(payload["nonce"])
        node = quote(str(payload.get("node", "")), safe="")
        app_token = _connect_token(0x61)
        wallet_token = _connect_token(0x62)
        management_token = _connect_token(0x63)
        relay_token = _connect_token(0x64)

        def role_uri(role: str, token: str) -> str:
            return (
                f"iroha://connect?sid={sid}&network_id={quote(network_id.literal, safe='')}"
                f"&app_pk={app_pk}&nonce={nonce}&node={node}&v=1&role={role}"
                f"&token={token}&relay={relay_token}"
            )

        return connect.ConnectSessionInfo(
            sid=sid,
            network_id=network_id,
            app_public_key=connect._decode_canonical_base64url(app_pk, 32, "app_pk"),
            nonce=connect._decode_canonical_base64url(nonce, 16, "nonce"),
            wallet_uri=role_uri("wallet", wallet_token),
            app_uri=role_uri("app", app_token),
            app_token=app_token,
            wallet_token=wallet_token,
            management_token=management_token,
            relay_token=relay_token,
        )


def _connect_token(fill: int) -> str:
    return base64.urlsafe_b64encode(bytes([fill]) * 32).rstrip(b"=").decode("ascii")


def _network(fill: int = 0xA5) -> connect.NetworkId:
    return connect.NetworkId.from_bytes(bytes([fill]) * 32)


def _key_pair() -> connect.ConnectKeyPair:
    private_key = bytes([0x44]) * 32
    return connect.ConnectKeyPair(
        private_key=private_key,
        public_key=connect.connect_public_key_from_private(private_key),
    )


def test_connect_codec_fails_closed_when_native_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(connect, "_CODEC_MODULE", None)

    def _raise_native_unavailable() -> object:
        raise RuntimeError("extension missing")

    monkeypatch.setattr(connect, "load_crypto_extension", _raise_native_unavailable)
    with pytest.raises(RuntimeError, match="native Connect codec unavailable"):
        connect._require_codec_module()


def test_connect_codec_caches_native_module(monkeypatch: pytest.MonkeyPatch) -> None:
    module = object()
    monkeypatch.setattr(connect, "_CODEC_MODULE", None)

    def _load_native() -> object:
        return module

    monkeypatch.setattr(connect, "load_crypto_extension", _load_native)
    assert connect._require_codec_module() is module
    assert connect._require_codec_module() is module


def test_generate_connect_sid_matches_deterministic_vector() -> None:
    result = connect.generate_connect_sid(
        network_id=_network(),
        app_public_key=bytes(range(32)),
        nonce=bytes(range(0xA0, 0xB0)),
    )

    assert result.sid_bytes.hex() == (
        "cd453da82e37ace00172fba4f2b8869bbb57c7c2ec30062e6267014223a6cc37"
    )
    assert result.sid_base64url == "zUU9qC43rOABcvuk8riGm7tXx8LsMAYuYmcBQiOmzDc"
    assert result.nonce == bytes(range(0xA0, 0xB0))


def test_generate_connect_sid_binds_network_app_key_and_nonce() -> None:
    app_pk = bytes(range(32))
    nonce = bytes(range(0xA0, 0xB0))
    expected = connect.generate_connect_sid(
        network_id=_network(), app_public_key=app_pk, nonce=nonce
    ).sid_bytes

    changed_app = bytearray(app_pk)
    changed_app[0] ^= 1
    changed_nonce = bytearray(nonce)
    changed_nonce[0] ^= 1
    assert connect.generate_connect_sid(
        network_id=_network(0xB5), app_public_key=app_pk, nonce=nonce
    ).sid_bytes != expected
    assert connect.generate_connect_sid(
        network_id=_network(), app_public_key=changed_app, nonce=nonce
    ).sid_bytes != expected
    assert connect.generate_connect_sid(
        network_id=_network(), app_public_key=app_pk, nonce=changed_nonce
    ).sid_bytes != expected


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        (
            {"app_public_key": bytes(31), "nonce": bytes(16)},
            "app_public_key must be 32 bytes",
        ),
        (
            {"app_public_key": bytes([1]) * 32, "nonce": bytes(15)},
            "nonce must be 16 bytes",
        ),
        (
            {"app_public_key": bytes(32), "nonce": bytes([1]) * 16},
            "app_public_key must not be all zero",
        ),
        (
            {"app_public_key": bytes([1]) * 32, "nonce": bytes(16)},
            "nonce must not be all zero",
        ),
    ],
)
def test_generate_connect_sid_rejects_malformed_inputs(
    kwargs: dict[str, object],
    match: str,
) -> None:
    with pytest.raises((TypeError, ValueError), match=match):
        connect.generate_connect_sid(network_id=_network(), **kwargs)  # type: ignore[arg-type]


def test_generate_connect_sid_has_no_chain_id_compatibility_shim() -> None:
    with pytest.raises(TypeError, match="chain_id"):
        connect.generate_connect_sid(  # type: ignore[call-arg]
            chain_id="legacy",
            app_public_key=bytes([1]) * 32,
            nonce=bytes([2]) * 16,
        )


def test_create_connect_session_preview_builds_canonical_uris() -> None:
    key_pair = _key_pair()

    preview = connect.create_connect_session_preview(
        network_id=_network(),
        node=" torii.devnet.example ",
        nonce=bytes(range(0xA0, 0xB0)),
        app_key_pair=key_pair,
    )

    assert preview.network_id == _network()
    assert preview.node == "torii.devnet.example"
    assert preview.app_key_pair is key_pair
    parsed = connect.parse_connect_uri(preview.wallet_uri)
    assert parsed.sid == preview.sid_base64url
    assert parsed.network_id == preview.network_id
    assert parsed.app_public_key == key_pair.public_key
    assert parsed.nonce == preview.nonce


def test_connect_uri_rejects_duplicate_and_substituted_identity() -> None:
    preview = connect.create_connect_session_preview(
        network_id=_network(),
        nonce=bytes(range(0xA0, 0xB0)),
        app_key_pair=_key_pair(),
    )
    with pytest.raises(ValueError, match="exactly once"):
        connect.parse_connect_uri(f"{preview.wallet_uri}&sid={preview.sid_base64url}")
    with pytest.raises(ValueError, match="sid does not match"):
        connect.parse_connect_uri(
            preview.wallet_uri.replace(
                quote(_network().literal, safe=""),
                quote(_network(0xB5).literal, safe=""),
            )
        )
    with pytest.raises(ValueError, match="retired"):
        connect.parse_connect_uri(f"{preview.wallet_uri}&chain_id=legacy")


def test_connect_uri_accepts_only_the_exact_v1_preview_schema() -> None:
    preview = connect.create_connect_session_preview(
        network_id=_network(),
        nonce=bytes(range(0xA0, 0xB0)),
        app_key_pair=_key_pair(),
    )

    with pytest.raises(ValueError, match="exactly 1"):
        connect.parse_connect_uri(preview.wallet_uri.replace("v=1", "v=2"))
    with pytest.raises(ValueError, match="unsupported"):
        connect.parse_connect_uri(f"{preview.wallet_uri}&token=discarded")
    with pytest.raises(ValueError, match="fragment"):
        connect.parse_connect_uri(f"{preview.wallet_uri}#ignored")
    with pytest.raises(ValueError, match="exactly 1"):
        connect.build_connect_uri(
            connect.ConnectUri(
                sid=preview.sid_base64url,
                network_id=preview.network_id,
                app_public_key=preview.app_key_pair.public_key,
                nonce=preview.nonce,
                version=2,
            )
        )


def test_connect_secret_containers_redact_and_validate_at_construction() -> None:
    key_pair = _key_pair()
    assert key_pair.private_key.hex() not in repr(key_pair)
    assert key_pair.public_key.hex() in repr(key_pair)
    with pytest.raises(ValueError, match="does not match"):
        connect.ConnectKeyPair(
            private_key=key_pair.private_key,
            public_key=bytes([0x99]) * 32,
        )
    with pytest.raises(TypeError, match="bytes-like"):
        connect.ConnectKeyPair(  # type: ignore[arg-type]
            private_key=32,
            public_key=key_pair.public_key,
        )
    with pytest.raises(TypeError, match="ConnectKeyPair"):
        connect.create_connect_session_preview(
            network_id=_network(),
            app_key_pair=object(),  # type: ignore[arg-type]
        )

    keys = connect.ConnectSessionKeys(
        app_to_wallet=bytes([0x81]) * 32,
        wallet_to_app=bytes([0x91]) * 32,
    )
    assert "81" * 32 not in repr(keys)
    assert "91" * 32 not in repr(keys)
    with pytest.raises(ValueError, match="distinct"):
        connect.ConnectSessionKeys(
            app_to_wallet=bytes([0x81]) * 32,
            wallet_to_app=bytes([0x81]) * 32,
        )

    tokens = connect.ConnectPreviewTokens(
        wallet=_connect_token(0x62),
        app=_connect_token(0x61),
        management=_connect_token(0x63),
        relay=_connect_token(0x64),
    )
    for token in (tokens.wallet, tokens.app, tokens.management, tokens.relay):
        assert token not in repr(tokens)


def test_native_connect_key_generation_does_not_derive_the_public_key_twice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CountingCodec:
        generated = 0

        def generate_connect_keypair(self):
            self.generated += 1
            return bytes([0x41]) * 32, bytes([0x51]) * 32

    codec = CountingCodec()
    monkeypatch.setattr(connect, "_require_codec_module", lambda: codec)

    pair = connect.generate_connect_keypair()

    assert pair.private_key == bytes([0x41]) * 32
    assert pair.public_key == bytes([0x51]) * 32
    assert codec.generated == 1


def test_bootstrap_connect_preview_session_registers_and_extracts_tokens() -> None:
    client = FakeToriiConnectClient()

    result = connect.bootstrap_connect_preview_session(
        client,
        network_id=_network(),
        node="torii.devnet.example",
        nonce=bytes(range(0xA0, 0xB0)),
        app_key_pair=_key_pair(),
    )

    assert client.calls == [
        {
            "sid": result.preview.sid_base64url,
            "network_id": _network().literal,
            "app_pk": connect._to_base64url(result.preview.app_key_pair.public_key),
            "nonce": connect._to_base64url(result.preview.nonce),
            "node": "torii.devnet.example",
        }
    ]
    assert result.session is not None
    assert result.session.sid == result.preview.sid_base64url
    assert result.tokens is not None
    assert result.tokens.wallet == _connect_token(0x62)
    assert result.tokens.app == _connect_token(0x61)
    assert result.tokens.management == _connect_token(0x63)
    assert result.tokens.relay == _connect_token(0x64)


def test_bootstrap_connect_preview_session_can_skip_registration() -> None:
    client = FakeToriiConnectClient()

    result = connect.bootstrap_connect_preview_session(
        client,
        network_id=_network(),
        register=False,
        nonce=bytes(range(0xA0, 0xB0)),
        app_key_pair=_key_pair(),
    )

    assert client.calls == []
    assert result.session is None
    assert result.tokens is None
    assert result.preview.sid_base64url


def test_bootstrap_connect_preview_session_rejects_bad_options_before_registration() -> None:
    client = FakeToriiConnectClient()

    with pytest.raises(ValueError, match="unsupported session option"):
        connect.bootstrap_connect_preview_session(
            client,
            network_id=_network(),
            session_options={"ttl_ms": 1000},
            nonce=bytes(range(0xA0, 0xB0)),
            app_key_pair=_key_pair(),
        )

    assert client.calls == []


def test_bootstrap_connect_preview_session_rejects_identity_substitution() -> None:
    alternate = connect.create_connect_session_preview(
        network_id=_network(0xB5),
        nonce=bytes(range(0xA0, 0xB0)),
        app_key_pair=_key_pair(),
    )
    client = FakeToriiConnectClient()
    alternate_payload = {
        "sid": alternate.sid_base64url,
        "network_id": alternate.network_id.literal,
        "app_pk": connect._to_base64url(alternate.app_key_pair.public_key),
        "nonce": connect._to_base64url(alternate.nonce),
    }
    client.response = FakeToriiConnectClient().create_connect_session(alternate_payload)

    with pytest.raises(ValueError, match="substituted"):
        connect.bootstrap_connect_preview_session(
            client,
            network_id=_network(),
            nonce=bytes(range(0xA0, 0xB0)),
            app_key_pair=_key_pair(),
        )

    assert len(client.calls) == 1


def test_connect_session_response_rejects_extensions_and_wallet_substitution() -> None:
    preview = connect.create_connect_session_preview(
        network_id=_network(),
        nonce=bytes(range(0xA0, 0xB0)),
        app_key_pair=_key_pair(),
    )
    payload = {
        "sid": preview.sid_base64url,
        "network_id": preview.network_id.literal,
        "app_pk": connect._to_base64url(preview.app_key_pair.public_key),
        "nonce": connect._to_base64url(preview.nonce),
    }
    info = FakeToriiConnectClient().create_connect_session(payload)
    assert isinstance(info, connect.ConnectSessionInfo)
    rendered = repr(info)
    for secret in (
        info.wallet_uri,
        info.app_uri,
        info.app_token,
        info.wallet_token,
        info.management_token,
        info.relay_token,
    ):
        assert secret not in rendered
    response = info.as_dict()
    response["ttl"] = "30"
    with pytest.raises(ValueError, match="inexact field set"):
        connect.ConnectSessionInfo.from_mapping(response)

    response.pop("ttl")
    response["wallet_uri"] = response["wallet_uri"].replace(
        "role=wallet", "role=app"
    )
    with pytest.raises(ValueError, match="substituted"):
        connect.ConnectSessionInfo.from_mapping(response)


def test_connect_session_rejects_sid_substitution_gaps_and_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sid = bytes([0x71]) * 32
    session = connect.ConnectSession(
        sid=sid,
        keys=connect.ConnectSessionKeys(
            app_to_wallet=bytes([0x81]) * 32,
            wallet_to_app=bytes([0x91]) * 32,
        ),
    )
    opened: list[int] = []

    def _open(_key: bytes, frame: connect.ConnectFrame) -> connect.ConnectEnvelope:
        opened.append(frame.sequence)
        return connect.ConnectEnvelope(
            sequence=frame.sequence,
            payload=connect.ConnectSignResultErrPayload(code="denied", message="denied"),
        )

    monkeypatch.setattr(connect, "open_connect_payload", _open)

    def _frame(frame_sid: bytes, sequence: int) -> connect.ConnectFrame:
        return connect.ConnectFrame(
            sid=frame_sid,
            direction=connect.ConnectDirection.WALLET_TO_APP,
            sequence=sequence,
            ciphertext=connect.ConnectCiphertext(
                direction=connect.ConnectDirection.WALLET_TO_APP,
                aead=b"ciphertext",
            ),
        )

    with pytest.raises(ValueError, match="sid"):
        session.decrypt(_frame(bytes([0x72]) * 32, 1))
    with pytest.raises(ValueError, match="exactly 1"):
        session.decrypt(_frame(sid, 2))
    assert session.decrypt(_frame(sid, 1)).sequence == 1
    with pytest.raises(ValueError, match="exactly 2"):
        session.decrypt(_frame(sid, 1))
    assert opened == [1]


def test_connect_frame_rejects_direction_substitution_and_zero_sequence() -> None:
    with pytest.raises(ValueError, match="direction must match"):
        connect.ConnectFrame(
            sid=bytes([1]) * 32,
            direction=connect.ConnectDirection.APP_TO_WALLET,
            sequence=1,
            ciphertext=connect.ConnectCiphertext(
                direction=connect.ConnectDirection.WALLET_TO_APP,
                aead=b"ciphertext",
            ),
        )
    with pytest.raises(ValueError, match="at least 1"):
        connect.ConnectFrame(
            sid=bytes([1]) * 32,
            direction=connect.ConnectDirection.APP_TO_WALLET,
            sequence=0,
            control=connect.ConnectControlPing(nonce=1),
        )


@pytest.mark.parametrize("value", [True, 1.5, "1", 0, 1 << 64])
def test_connect_replay_counters_reject_coercion_and_out_of_range_values(
    value: object,
) -> None:
    sid = bytes([1]) * 32
    payload = connect.ConnectSignResultErrPayload(code="denied", message="denied")
    keys = connect.ConnectSessionKeys(
        app_to_wallet=bytes([0x81]) * 32,
        wallet_to_app=bytes([0x91]) * 32,
    )
    constructors = (
        lambda: connect.ConnectFrame(
            sid=sid,
            direction=connect.ConnectDirection.APP_TO_WALLET,
            sequence=value,  # type: ignore[arg-type]
            control=connect.ConnectControlPing(nonce=1),
        ),
        lambda: connect.ConnectEnvelope(sequence=value, payload=payload),  # type: ignore[arg-type]
        lambda: connect.ConnectSessionState(
            sid=sid,
            next_sequence_app_to_wallet=value,  # type: ignore[arg-type]
        ),
        lambda: connect.ConnectSession(
            sid=sid,
            keys=keys,
            app_initial_sequence=value,  # type: ignore[arg-type]
        ),
        lambda: connect.seal_connect_payload(
            bytes([2]) * 32,
            sid,
            direction=connect.ConnectDirection.APP_TO_WALLET,
            sequence=value,  # type: ignore[arg-type]
            payload=payload,
        ),
    )

    for constructor in constructors:
        with pytest.raises((TypeError, ValueError), match="integer"):
            constructor()


def test_connect_session_state_from_dict_rejects_boolean_counters() -> None:
    payload = connect.ConnectSessionState(sid=bytes([1]) * 32).to_dict()
    payload["next_sequence"]["app_to_wallet"] = True

    with pytest.raises(TypeError, match="integer"):
        connect.ConnectSessionState.from_dict(payload)


@pytest.mark.parametrize("value", [True, 1.5, "1", -1, 1 << 16])
def test_connect_control_codes_are_exact_u16_values(value: object) -> None:
    with pytest.raises((TypeError, ValueError), match="integer"):
        connect.ConnectControlReject(
            code=value,  # type: ignore[arg-type]
            code_id="REJECTED",
            reason="denied",
        )
    with pytest.raises((TypeError, ValueError), match="integer"):
        connect.ConnectControlClose(
            role=connect.ConnectRole.APP,
            code=value,  # type: ignore[arg-type]
            reason="closed",
            retryable=False,
        )


@pytest.mark.parametrize("value", [True, 1.5, "1", -1, 1 << 64])
def test_connect_control_nonces_are_exact_u64_values(value: object) -> None:
    with pytest.raises((TypeError, ValueError), match="integer"):
        connect.ConnectControlPing(nonce=value)  # type: ignore[arg-type]
    with pytest.raises((TypeError, ValueError), match="integer"):
        connect.ConnectControlPong(nonce=value)  # type: ignore[arg-type]


def test_connect_control_nonce_zero_is_canonical() -> None:
    assert connect.ConnectControlPing(nonce=0).nonce == 0
    assert connect.ConnectControlPong(nonce=0).nonce == 0


def test_connect_close_retryable_requires_an_exact_boolean() -> None:
    with pytest.raises(TypeError, match="boolean"):
        connect.ConnectControlClose(
            role=connect.ConnectRole.APP,
            code=1,
            reason="closed",
            retryable=1,  # type: ignore[arg-type]
        )


def test_connect_sign_result_ok_normalizes_exact_ed25519_algorithm() -> None:
    payload = connect.ConnectSignResultOkPayload(
        signature=bytes([0x11]) * 64,
        algorithm="Ed25519",
    )

    assert payload.algorithm == "ed25519"
    assert payload.to_wire_dict()["signature"]["algorithm"] == "ed25519"


@pytest.mark.parametrize(
    "algorithm",
    [
        "secp256k1",
        "",
        " ",
        " Ed25519",
        "Ed25519 ",
        "\tEd25519",
        "Ed25519\n",
        "ed\t25519",
        "\u00a0Ed25519",
        "Ed25519\u00a0",
        "ed\u200b25519",
        "\u0435d25519",
        "ed\uff0d25519",
    ],
)
def test_connect_sign_result_ok_rejects_confusable_algorithms(algorithm: str) -> None:
    with pytest.raises(ValueError, match="unsupported wallet signature algorithm"):
        connect.ConnectSignResultOkPayload(
            signature=bytes([0x11]) * 64,
            algorithm=algorithm,
        )


@pytest.mark.parametrize(
    "algorithm",
    [
        "",
        " ",
        " Ed25519",
        "Ed25519 ",
        "\tEd25519",
        "Ed25519\n",
        "\u00a0Ed25519",
        "Ed25519\u00a0",
    ],
)
def test_connect_sign_result_ok_from_dict_rejects_padded_algorithm(
    algorithm: str,
) -> None:
    with pytest.raises(ValueError, match="unsupported wallet signature algorithm"):
        connect.ConnectSignResultOkPayload.from_dict(
            {
                "signature": {
                    "algorithm": algorithm,
                    "signature": bytes([0x11]) * 64,
                }
            }
        )


@pytest.mark.parametrize(
    "algorithm",
    [
        "secp256k1",
        "",
        " ",
        " Ed25519",
        "Ed25519 ",
        "\tEd25519",
        "Ed25519\n",
        "ed\t25519",
        "\u00a0Ed25519",
        "Ed25519\u00a0",
        "ed\u200b25519",
        "\u0435d25519",
        "ed\uff0d25519",
    ],
)
def test_connect_control_approve_rejects_confusable_algorithms(algorithm: str) -> None:
    with pytest.raises(ValueError, match="unsupported wallet signature algorithm"):
        connect.ConnectControlApprove(
            wallet_public_key=bytes([0x22]) * 32,
            account_id="account-i105",
            signature=bytes([0x33]) * 64,
            algorithm=algorithm,
        )


@pytest.mark.parametrize(
    "algorithm",
    [
        "",
        " ",
        " Ed25519",
        "Ed25519 ",
        "\tEd25519",
        "Ed25519\n",
        "\u00a0Ed25519",
        "Ed25519\u00a0",
    ],
)
def test_connect_control_approve_from_dict_rejects_padded_algorithm(
    algorithm: str,
) -> None:
    with pytest.raises(ValueError, match="unsupported wallet signature algorithm"):
        connect.ConnectControlApprove.from_dict(
            {
                "wallet_public_key": bytes([0x22]) * 32,
                "account_id": "account-i105",
                "signature": bytes([0x33]) * 64,
                "algorithm": algorithm,
            }
        )


def _mock_otool(
    monkeypatch: pytest.MonkeyPatch,
    output: str,
) -> None:
    monkeypatch.setattr(native_loader.sys, "platform", "darwin")
    monkeypatch.setattr(
        native_loader.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=["otool", "-L"],
            returncode=0,
            stdout=output,
            stderr="",
        ),
    )


def _otool_output(candidate, *dependencies: str) -> str:
    linked = "\n".join(
        f"\t{dependency} (compatibility version 3.12.0, current version 3.12.0)"
        for dependency in dependencies
    )
    return f"{candidate}:\n{linked}\n"


def test_native_loader_accepts_current_python_framework(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    candidate = tmp_path / "_crypto.abi3.so"
    candidate.write_bytes(b"")
    current = (
        f"{native_loader.sys.version_info.major}."
        f"{native_loader.sys.version_info.minor}"
    )
    _mock_otool(
        monkeypatch,
        _otool_output(
            candidate,
            f"/Library/Frameworks/Python.framework/Versions/{current}/Python",
        ),
    )

    native_loader._assert_extension_compatible(candidate)


def test_native_loader_rejects_wrong_python_framework(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    candidate = tmp_path / "_crypto.abi3.so"
    candidate.write_bytes(b"")
    current = (
        f"{native_loader.sys.version_info.major}."
        f"{native_loader.sys.version_info.minor}"
    )
    wrong = "3.14" if current != "3.14" else "3.13"
    _mock_otool(
        monkeypatch,
        _otool_output(
            candidate,
            f"/Library/Frameworks/Python.framework/Versions/{wrong}/Python",
        ),
    )

    with pytest.raises(RuntimeError, match="links Python"):
        native_loader._assert_extension_compatible(candidate)


def test_native_loader_rejects_current_stale_direct_libpython_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    candidate = tmp_path / "_crypto.abi3.so"
    candidate.write_bytes(b"")
    _mock_otool(
        monkeypatch,
        _otool_output(
            candidate,
            _STALE_LIBPYTHON_PATH,
        ),
    )

    with pytest.raises(RuntimeError, match="links directly to an alternate Python runtime"):
        native_loader._assert_extension_compatible(candidate)


def test_native_loader_rejects_direct_versioned_libpython_so(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    candidate = tmp_path / "_crypto.abi3.so"
    candidate.write_bytes(b"")
    _mock_otool(
        monkeypatch,
        _otool_output(candidate, "@rpath/libpython3.12.so.1.0"),
    )

    with pytest.raises(RuntimeError, match="links directly to an alternate Python runtime"):
        native_loader._assert_extension_compatible(candidate)


def test_native_loader_rejects_direct_runtime_before_import(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    candidate = tmp_path / "_crypto.abi3.so"
    candidate.write_bytes(b"")
    _mock_otool(monkeypatch, _otool_output(candidate, _STALE_LIBPYTHON_PATH))
    spec = native_loader.importlib.machinery.ModuleSpec(
        "iroha_native._crypto",
        loader=native_loader.importlib.machinery.ExtensionFileLoader("iroha_native._crypto", str(candidate)),
        origin=str(candidate),
    )
    loader_source = tmp_path / "_loader.py"
    loader_source.write_text("# canonical test loader location\n")
    monkeypatch.setattr(native_loader, "__file__", str(loader_source))
    monkeypatch.delitem(native_loader.sys.modules, "iroha_native._crypto", raising=False)
    monkeypatch.setattr(native_loader, "_verified_native_module", None)
    monkeypatch.setattr(native_loader.importlib.machinery.PathFinder, "find_spec", lambda _name, _path: spec)

    def fail_import(_spec) -> None:
        pytest.fail("stale extension reached importlib before linkage rejection")

    monkeypatch.setattr(native_loader.importlib.util, "module_from_spec", fail_import)

    with pytest.raises(RuntimeError, match="links directly to an alternate Python runtime"):
        native_loader.load_crypto_extension()


def test_native_loader_rejects_malformed_python_dependency(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    candidate = tmp_path / "_crypto.abi3.so"
    candidate.write_bytes(b"")
    _mock_otool(
        monkeypatch,
        _otool_output(candidate, "@rpath/libpython.dylib"),
    )

    with pytest.raises(RuntimeError, match="unrecognized Python runtime dependency"):
        native_loader._assert_extension_compatible(candidate)


def test_native_loader_rejects_multiple_python_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    candidate = tmp_path / "_crypto.abi3.so"
    candidate.write_bytes(b"")
    current = (
        f"{native_loader.sys.version_info.major}."
        f"{native_loader.sys.version_info.minor}"
    )
    _mock_otool(
        monkeypatch,
        _otool_output(
            candidate,
            f"/Library/Frameworks/Python.framework/Versions/{current}/Python",
            f"@rpath/libpython{current}.dylib",
        ),
    )

    with pytest.raises(RuntimeError, match="links multiple Python runtimes"):
        native_loader._assert_extension_compatible(candidate)


def test_native_loader_accepts_extension_without_python_runtime_dependency(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    candidate = tmp_path / "_crypto.abi3.so"
    candidate.write_bytes(b"")
    _mock_otool(
        monkeypatch,
        _otool_output(
            candidate,
            "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
            "/usr/lib/libSystem.B.dylib",
        ),
    )

    native_loader._assert_extension_compatible(candidate)


def test_native_loader_rejects_unrecognized_python_framework_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    candidate = tmp_path / "_crypto.abi3.so"
    candidate.write_bytes(b"")
    _mock_otool(
        monkeypatch,
        _otool_output(
            candidate,
            "/Library/Frameworks/Python.framework/Versions/Current/Python",
        ),
    )

    with pytest.raises(RuntimeError, match="unrecognized Python runtime dependency"):
        native_loader._assert_extension_compatible(candidate)


def test_native_loader_rejects_failed_otool_inspection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    candidate = tmp_path / "_crypto.abi3.so"
    candidate.write_bytes(b"")
    monkeypatch.setattr(native_loader.sys, "platform", "darwin")
    monkeypatch.setattr(
        native_loader.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=["otool", "-L"],
            returncode=1,
            stdout="",
            stderr="malformed object",
        ),
    )

    with pytest.raises(RuntimeError, match="otool exited with status 1"):
        native_loader._assert_extension_compatible(candidate)


def test_native_loader_rejects_unavailable_otool(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    candidate = tmp_path / "_crypto.abi3.so"
    candidate.write_bytes(b"")
    monkeypatch.setattr(native_loader.sys, "platform", "darwin")

    def fail_otool(*_args, **_kwargs):
        raise OSError("otool unavailable")

    monkeypatch.setattr(native_loader.subprocess, "run", fail_otool)

    with pytest.raises(RuntimeError, match="could not inspect Python linkage"):
        native_loader._assert_extension_compatible(candidate)
