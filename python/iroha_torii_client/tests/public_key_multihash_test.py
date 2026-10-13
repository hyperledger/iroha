"""Exact canonical public-key multihash literals shared by status and governance decoders."""

import pytest
from iroha_torii_client._public_key_multihash import decode_canonical_public_key_multihash

ED25519 = "ed012066BE7E332C7A453332BD9D0A7F7DB055F5C5EF1A06ADA66D98B39FB6810C473A"
BLS_NORMAL = (
    "ea013097F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB"
)


def test_canonical_literals_return_their_ordering_key():
    literal, (ordinal, payload) = decode_canonical_public_key_multihash(ED25519, "key")
    assert literal == ED25519
    assert ordinal == 0
    assert payload == bytes.fromhex(ED25519[6:])
    _, (bls_ordinal, bls_payload) = decode_canonical_public_key_multihash(BLS_NORMAL, "key")
    assert bls_ordinal == 2
    assert len(bls_payload) == 48


@pytest.mark.parametrize(
    "literal",
    [
        ED25519[:6] + ED25519[6:].lower(),  # noncanonical payload spelling
        ED25519.upper(),  # noncanonical header spelling
        ED25519[:-2],  # payload shorter than its declared length
        "ed80012066BE7E332C7A453332BD9D0A7F7DB055F5C5EF1A06ADA66D98B39FB6810C473A",  # overlong varint
        "ff0120" + ED25519[6:],  # unsupported algorithm code
        "ed0120" + "00" * 32,  # not a prime-order Ed25519 point
        " " + ED25519,
        "",
        b"ed0120",
    ],
)
def test_noncanonical_literals_are_rejected_with_context(literal):
    with pytest.raises(TypeError, match="signer"):
        decode_canonical_public_key_multihash(literal, "signer")
