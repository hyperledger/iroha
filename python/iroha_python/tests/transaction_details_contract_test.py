"""Wrapper contract units only; Rust owns native details receipt acceptance."""
from types import SimpleNamespace
import json
import pytest
import iroha_python.crypto as crypto


def values():
    return dict(transaction_hash="11"*32,details_response_bytes=b"original-details-frame",
        native_finality_proof_chain_json="[native-proof]",
        expected_network_id=crypto.NetworkId.from_bytes(bytes([0xa5])*32),
        expected_chain="selected-chain",trusted_checkpoint=b"selected-checkpoint",
        expected_chain_discriminant=369)


def test_details_wrapper_forwards_original_bytes_and_selected_context(monkeypatch):
    supplied=values();calls=[]
    def verify(*args,**kwargs):
        calls.append((args,kwargs));return (json.dumps({"result_ok":False}),b"promoted")
    monkeypatch.setattr(crypto,"_crypto",SimpleNamespace(verify_transaction_details_inclusion=verify))
    result=crypto.verify_transaction_details_inclusion(**supplied)
    assert calls==[((supplied["transaction_hash"],supplied["details_response_bytes"],
        supplied["native_finality_proof_chain_json"],supplied["expected_network_id"],
        supplied["expected_chain"],supplied["trusted_checkpoint"]),{"expected_chain_discriminant":369})]
    assert result=={"result_ok":False,"promoted_checkpoint":b"promoted"}


@pytest.mark.parametrize("field,value",[("details_response_bytes",bytearray(b"x")),
    ("details_response_bytes",b""),("trusted_checkpoint",b""),
    ("expected_chain_discriminant",True),("expected_chain_discriminant",65536),
    ("transaction_hash","11"*31+"10"),("transaction_hash","0x"+"11"*32),
    ("native_finality_proof_chain_json",""),("expected_chain","")])
def test_details_wrapper_refuses_before_native(monkeypatch,field,value):
    def unexpected(*args,**kwargs):raise AssertionError("native must not be called")
    monkeypatch.setattr(crypto,"_crypto",SimpleNamespace(verify_transaction_details_inclusion=unexpected))
    supplied=values();supplied[field]=value
    with pytest.raises((TypeError,ValueError)):crypto.verify_transaction_details_inclusion(**supplied)


def test_details_builder_and_carrier_wrapper_preserve_original_inputs(monkeypatch):
    supplied=values();calls=[]
    def build(*args,**kwargs):calls.append((args,kwargs));return b"signed-query"
    def carrier(*args):calls.append(args);return "33"*32
    monkeypatch.setattr(crypto,"_crypto",SimpleNamespace(build_find_transaction_details_query=build,
        transaction_details_carrier_block_hash=carrier))
    key=bytes([0x44])*32
    wire=crypto.build_find_transaction_details_query("selected-reader",key,supplied["expected_network_id"],
        supplied["transaction_hash"],chain_discriminant=369)
    assert wire==b"signed-query"
    assert calls==[(("selected-reader",key,supplied["expected_network_id"],supplied["transaction_hash"]),{"chain_discriminant":369})]
    assert crypto.transaction_details_carrier_block_hash(supplied["transaction_hash"],supplied["details_response_bytes"])=="33"*32
    assert calls[-1]==(supplied["transaction_hash"],supplied["details_response_bytes"])


def test_details_wrapper_preserves_native_refusal(monkeypatch):
    refusal=ValueError("original native refusal")
    def refused(*args,**kwargs):raise refusal
    monkeypatch.setattr(crypto,"_crypto",SimpleNamespace(verify_transaction_details_inclusion=refused))
    with pytest.raises(ValueError) as seen:crypto.verify_transaction_details_inclusion(**values())
    assert seen.value is refusal
