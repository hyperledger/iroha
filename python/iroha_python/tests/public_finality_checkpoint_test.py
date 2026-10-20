"""Wrapper forwarding/refusal tests only; native Core tests own proof verification."""
import json
from types import SimpleNamespace
import pytest
import iroha_python.crypto as crypto


def values():
    return dict(genesis=b"wrapper-contract-only", proof_wires=(b"one", b"two"),
                expected_network_id=crypto.NetworkId.from_bytes(bytes([1])*32),
                expected_chain="selected-public-chain", expected_genesis_sha256=bytes([2])*32)


def test_public_checkpoint_wrapper_preserves_independent_pins(monkeypatch):
    supplied=values(); seen=[]
    metadata=dict(network_id=supplied["expected_network_id"].literal,chain_id=supplied["expected_chain"],
                  genesis_sha256=supplied["expected_genesis_sha256"].hex(),root_scope="Global",height=2,
                  proof_count=2,block_hash="a"*64,context_id="b"*64)
    def stub(genesis, proof_wires, **pins):
        seen.append((genesis,proof_wires,pins))
        return json.dumps(metadata),b"opaque-wrapper-test-checkpoint","[{}]"
    monkeypatch.setattr(crypto,"_crypto",SimpleNamespace(authenticate_public_finality_checkpoint_v1=stub))
    output=crypto.authenticate_public_finality_checkpoint_v1(**supplied)
    assert seen == [(supplied["genesis"],supplied["proof_wires"],{k:v for k,v in supplied.items() if k.startswith("expected_")})]
    assert output["metadata"] == metadata
    assert output["checkpoint"] == b"opaque-wrapper-test-checkpoint"


@pytest.mark.parametrize("field,value", [
    ("genesis", bytearray(b"x")), ("genesis",b""),
    ("proof_wires", [b"one",b"two"]), ("proof_wires",(b"one",)),
    ("proof_wires",(b"one",bytearray(b"two"))), ("proof_wires",(b"",b"two")),
    ("proof_wires",(b"x",)*4097), ("proof_wires",(bytes(16*1024*1024),b"x")),
    ("expected_chain"," padded"), ("expected_chain","x"*513), ("expected_chain","x\0y"),
    ("expected_chain","x\ny"), ("expected_chain","x\ty"),
    ("expected_chain","x\x7fy"), ("expected_chain","x\x85y"),
    ("expected_genesis_sha256",bytes(32)), ("expected_genesis_sha256",bytearray([1]*32)),
])
def test_public_checkpoint_wrapper_rejects_before_native(monkeypatch,field,value):
    def unexpected(*args,**kwargs): raise AssertionError("native must not be entered")
    monkeypatch.setattr(crypto,"_crypto",SimpleNamespace(authenticate_public_finality_checkpoint_v1=unexpected))
    arguments=values();arguments[field]=value
    with pytest.raises((TypeError,ValueError)):
        crypto.authenticate_public_finality_checkpoint_v1(**arguments)


def test_public_checkpoint_wrapper_does_not_reclassify_native_refusal(monkeypatch):
    class NativeRefusal(Exception): pass
    refusal=NativeRefusal("original bounded decode refused");refusal.kind="decode_resource";refusal.phase="proof_decode"
    def refused(*args,**kwargs): raise refusal
    monkeypatch.setattr(crypto,"_crypto",SimpleNamespace(authenticate_public_finality_checkpoint_v1=refused))
    with pytest.raises(NativeRefusal) as seen:crypto.authenticate_public_finality_checkpoint_v1(**values())
    assert seen.value is refusal


def test_public_checkpoint_wrapper_refuses_mutable_or_wrong_context_result(monkeypatch):
    for output in [("{}",bytearray(b"checkpoint"),"[{}]"),("{}",b"checkpoint","[{}]"),["{}",b"checkpoint","[{}]"]]:
        monkeypatch.setattr(crypto,"_crypto",SimpleNamespace(authenticate_public_finality_checkpoint_v1=lambda *args,**kwargs:output))
        with pytest.raises(RuntimeError):crypto.authenticate_public_finality_checkpoint_v1(**values())


def test_public_checkpoint_exception_is_public_and_native():
    import iroha_python
    from iroha_native import load_crypto_extension
    assert iroha_python.PublicFinalityReadError is crypto.PublicFinalityReadError
    assert crypto.PublicFinalityReadError is load_crypto_extension().PublicFinalityReadError
