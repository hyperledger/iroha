"""High-level crypto helpers backed by `iroha_crypto` via PyO3 bindings."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from types import MappingProxyType
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Final,
    Iterable,
    Mapping,
    Optional,
    TypeAlias,
    Union,
    cast,
)

from iroha_native import load_crypto_extension

from ._validation import _normalize_mapping_payload, _optional_uint
from .address import AccountAddress

_crypto = load_crypto_extension()

# Exact genesis-derived transaction domain. Construction is closed in the
# native boundary so ordinary signing APIs cannot reinterpret labels or bare
# byte strings as a NetworkId.
if TYPE_CHECKING:
    class NetworkId(Any):
        """Static view of the required native ``NetworkId`` value."""

        literal: str

        @classmethod
        def parse(cls, literal: str) -> "NetworkId": ...

        def to_bytes(self) -> bytes: ...
else:
    NetworkId = _crypto.NetworkId


def _require_network_id(value: Any, context: str = "network_id") -> NetworkId:
    if not isinstance(value, NetworkId):
        raise TypeError(f"{context} must be a NetworkId")
    return value

ED25519_ALGORITHM: Final[str] = "ed25519"
SECP256K1_ALGORITHM: Final[str] = "secp256k1"
ML_DSA_ALGORITHM: Final[str] = "ml-dsa"
GOST_3410_2012_256_PARAMSET_A_ALGORITHM: Final[str] = "gost3410-2012-256-paramset-a"
GOST_3410_2012_256_PARAMSET_B_ALGORITHM: Final[str] = "gost3410-2012-256-paramset-b"
GOST_3410_2012_256_PARAMSET_C_ALGORITHM: Final[str] = "gost3410-2012-256-paramset-c"
GOST_3410_2012_512_PARAMSET_A_ALGORITHM: Final[str] = "gost3410-2012-512-paramset-a"
GOST_3410_2012_512_PARAMSET_B_ALGORITHM: Final[str] = "gost3410-2012-512-paramset-b"
BLS_NORMAL_ALGORITHM: Final[str] = "bls_normal"
BLS_SMALL_ALGORITHM: Final[str] = "bls_small"
SM2_ALGORITHM: Final[str] = "sm2"
PRIVACY_REQUIRED_BRIDGE_ABI_VERSION: Final[int] = 29
PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES: Final[int] = 256 * 1024
PRIVACY_EXACT12_CAPABILITY_MANIFEST_ARCHIVE_MAX_BYTES_V1: Final[int] = 256 * 1024
PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1: Final[Mapping[str, int]] = MappingProxyType(
    {
        "VALID": 0,
        "NULL_POINTER": 1,
        "EMPTY": 2,
        "ARCHIVE_TOO_LARGE": 3,
        "DECODE_RESOURCE_LIMIT": 4,
        "SCHEMA_MISMATCH": 5,
        "NON_CANONICAL": 6,
        "MALFORMED_ARCHIVE": 7,
        "INVALID_CATALOG": 8,
    }
)
PRIVACY_EXACT12_CAPABILITY_MANIFEST_VALIDATION_STATUS_V1: Final[Mapping[str, int]] = (
    MappingProxyType(
        {
            "VALID": 0,
            "NULL_POINTER": 1,
            "EMPTY": 2,
            "ARCHIVE_TOO_LARGE": 3,
            "DECODE_RESOURCE_LIMIT": 4,
            "SCHEMA_MISMATCH": 5,
            "NON_CANONICAL": 6,
            "MALFORMED_ARCHIVE": 7,
            "INVALID_MANIFEST": 8,
        }
    )
)
_PRIVACY_MAX_BRIDGE_ABI_VERSION: Final[int] = 0xFFFF_FFFF
SUPPORTED_CRYPTO_ALGORITHMS: Final[tuple[str, ...]] = tuple(
    _crypto.supported_crypto_algorithms()
)

ED25519_PRIVATE_KEY_LENGTH: Final[int] = 32
ED25519_PUBLIC_KEY_LENGTH: Final[int] = 32
ED25519_SIGNATURE_LENGTH: Final[int] = 64
_ED25519_MULTIHASH_PREFIX: Final[str] = "ed0120"
_DEFAULT_I105_DISCRIMINANT: Final[int] = 0x02F1
_MAX_CONTRACT_ARGUMENT_RECORD_BYTES: Final[int] = 1024 * 1024
# Keep this byte bound aligned with the native V1 CancelAssetLock builders in
# every SDK. The derived EscrowId remains a fixed 32-byte wire value.
CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1: Final[int] = 4_096
ContractArguments: TypeAlias = Union[bytes, bytearray, memoryview]

SM2_PRIVATE_KEY_LENGTH: Final[int] = 32
SM2_PUBLIC_KEY_LENGTH: Final[int] = 65
SM2_SIGNATURE_LENGTH: Final[int] = 64
SM2_DEFAULT_DISTINGUISHED_ID: Final[str] = _crypto.sm2_default_distid()

__all__ = [
    "ED25519_ALGORITHM",
    "SECP256K1_ALGORITHM",
    "ML_DSA_ALGORITHM",
    "GOST_3410_2012_256_PARAMSET_A_ALGORITHM",
    "GOST_3410_2012_256_PARAMSET_B_ALGORITHM",
    "GOST_3410_2012_256_PARAMSET_C_ALGORITHM",
    "GOST_3410_2012_512_PARAMSET_A_ALGORITHM",
    "GOST_3410_2012_512_PARAMSET_B_ALGORITHM",
    "BLS_NORMAL_ALGORITHM",
    "BLS_SMALL_ALGORITHM",
    "SM2_ALGORITHM",
    "PRIVACY_REQUIRED_BRIDGE_ABI_VERSION",
    "PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES",
    "PRIVACY_EXACT12_CAPABILITY_MANIFEST_ARCHIVE_MAX_BYTES_V1",
    "PRIVACY_EXACT12_CAPABILITY_MANIFEST_VALIDATION_STATUS_V1",
    "PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1",
    "SUPPORTED_CRYPTO_ALGORITHMS",
    "ED25519_PRIVATE_KEY_LENGTH",
    "ED25519_PUBLIC_KEY_LENGTH",
    "ED25519_SIGNATURE_LENGTH",
    "SM2_PRIVATE_KEY_LENGTH",
    "SM2_PUBLIC_KEY_LENGTH",
    "SM2_SIGNATURE_LENGTH",
    "SM2_DEFAULT_DISTINGUISHED_ID",
    "CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1",
    "CryptoKeyPair",
    "Ed25519KeyPair",
    "Sm2KeyPair",
    "Instruction",
    "ContractCall",
    "NetworkId",
    "TransactionExecutableEntry",
    "PrivacyNativeActionBuildResultV1",
    "PrivacyExact12CapabilityManifestV1",
    "SignedTransactionEnvelope",
    "TransactionBuilder",
    "ConfidentialKeyset",
    "DomainId",
    "AccountId",
    "AssetDefinitionId",
    "AssetId",
    "normalize_crypto_algorithm",
    "supported_crypto_algorithms",
    "derive_keypair_from_seed",
    "derive_ed25519_keypair_from_seed",
    "generate_keypair",
    "generate_ed25519_keypair",
    "load_keypair",
    "load_keypair_from_multihash",
    "load_ed25519_keypair",
    "load_ed25519_keypair_from_hex",
    "derive_sm2_keypair_from_seed",
    "generate_sm2_keypair",
    "load_sm2_keypair",
    "sm2_public_key_multihash",
    "ed25519_public_key_multihash",
    "ed25519_public_key_account_id",
    "build_signed_transaction",
    "build_find_asset_escrow_query",
    "build_find_asset_escrows_by_seller_query",
    "build_find_asset_escrows_by_buyer_query",
    "build_find_committed_transaction_query",
    "build_find_block_by_hash_query",
    "committed_transaction_carrier_block_hash",
    "verify_committed_transaction_inclusion",
    "hash_blake2b_32",
    "decode_zk_vk_transaction_payload",
    "public_key_multihash",
    "private_key_multihash",
    "parse_public_key_multihash",
    "parse_private_key_multihash",
    "sign",
    "sign_ed25519",
    "sign_sm2",
    "decode_transaction_receipt_json",
    "inspect_transaction_submission_v1",
    "verify_transaction_submission_receipt_v1",
    "inspect_sorafs_orderbook_submission_for_discriminant_v1",
    "verify_sorafs_orderbook_submission_receipt_v1",
    "verify_signed_transaction_versioned",
    "verify",
    "verify_ed25519",
    "verify_sm2",
    "derive_confidential_keyset",
    "derive_confidential_keyset_from_hex",
    "compute_confidential_root_v2",
    "derive_confidential_next_zero_path_v2",
    "default_confidential_diversifier_v2",
    "derive_confidential_diversifier_v2",
    "derive_confidential_owner_tag_v2",
    "derive_confidential_note_v2",
    "confidential_transfer_v2_verifying_key_registration_payload_v1",
    "confidential_unshield_v3_verifying_key_registration_payload_v1",
    "privacy_bridge_abi_version",
    "is_privacy_native_available",
    "privacy_compiled_profile_catalog_v1",
    "privacy_exact12_capability_manifest_v1",
    "privacy_validate_exact12_capability_manifest_v1",
    "canonical_genesis_header_hash_v1",
    "canonical_signed_transaction_hash_v1",
    "signed_transaction_envelope_from_versioned_v1",
    "account_faucet_claim_hash_v1",
    "verify_prepared_transaction_context_v1",
    "verify_account_onboarding_receipt_v1",
    "inspect_privacy_exact12_action_driver_transaction_context_v1",
    "privacy_vega_device_authentication_digest_v1",
    "inspect_signed_privacy_zk_ace_transfer_action_v1",
    "inspect_signed_privacy_bootle_lantern_presentation_action_v1",
    "inspect_signed_privacy_jindo_action_v1",
    "inspect_signed_privacy_verange_action_v1",
    "inspect_signed_privacy_vega_action_v1",
    "inspect_signed_privacy_zk_x509_identity_presentation_action_v1",
    "inspect_signed_privacy_zk_ams_batch_admission_action_v1",
    "inspect_signed_privacy_zk_ams_provision_account_action_v1",
    "inspect_signed_privacy_anonymous_pgc_payment_action_v1",
    "inspect_signed_privacy_orchard_note_action_v1",
    "inspect_signed_privacy_fcmp_membership_payment_action_v1",
    "inspect_signed_privacy_ivm_private_note_action_v1",
    "inspect_signed_privacy_pq_masp_note_action_v1",
    "sm2_fixture_from_seed",
]


@dataclass(frozen=True)
class ContractCall:
    """One deployed-contract invocation in an ordered transaction batch."""

    contract_address: str
    expected_code_hash_hex: str
    entrypoint: str
    arguments: Optional[ContractArguments] = None

    def __post_init__(self) -> None:
        for value, context in (
            (self.contract_address, "contract_address"),
            (self.expected_code_hash_hex, "expected_code_hash_hex"),
            (self.entrypoint, "entrypoint"),
        ):
            if not isinstance(value, str):
                raise TypeError(f"{context} must be a string")
            if not value:
                raise ValueError(f"{context} must be non-empty")
            if value != value.strip():
                raise ValueError(f"{context} must not contain surrounding whitespace")

        if len(self.expected_code_hash_hex) != 64:
            raise ValueError("expected_code_hash_hex must contain exactly 32 bytes")
        try:
            code_hash = bytes.fromhex(self.expected_code_hash_hex)
        except ValueError as exc:
            raise ValueError("expected_code_hash_hex must be valid hexadecimal") from exc
        if len(code_hash) != 32:
            raise ValueError("expected_code_hash_hex must contain exactly 32 bytes")
        if code_hash[-1] & 1 != 1:
            raise ValueError("expected_code_hash_hex must have its least significant bit set")

        if self.arguments is None:
            return
        if not isinstance(self.arguments, (bytes, bytearray, memoryview)):
            raise TypeError("arguments must be bytes-like when provided")
        arguments = bytes(self.arguments)
        if len(arguments) > _MAX_CONTRACT_ARGUMENT_RECORD_BYTES:
            raise ValueError(
                f"arguments exceed the {_MAX_CONTRACT_ARGUMENT_RECORD_BYTES}-byte limit"
            )
        object.__setattr__(self, "arguments", arguments)


def _native_instruction_builder(name: str) -> Any:
    """Return one required native instruction builder without compatibility fallback."""

    builder = getattr(_crypto.Instruction, name, None)
    if builder is None:
        raise RuntimeError(
            f"iroha_native._crypto is missing Instruction.{name}(); rebuild the extension"
        )
    return builder


def _native_issue_replication_order(
    order_id: str,
    order_payload: str,
    issued_epoch: int,
    deadline_epoch: int,
    musubi_archive: str | None,
) -> Any:
    return _native_instruction_builder("issue_replication_order")(
        order_id,
        order_payload,
        issued_epoch,
        deadline_epoch,
        musubi_archive,
    )


def _native_complete_replication_order(
    order_id: str,
    provider_id: str,
    completion_epoch: int,
    expected_authority: Mapping[str, Any],
    expected_assignment_revision: int,
    finalized_anchor: Mapping[str, Any],
) -> Any:
    return _native_instruction_builder("complete_replication_order")(
        order_id,
        provider_id,
        completion_epoch,
        dict(expected_authority),
        expected_assignment_revision,
        dict(finalized_anchor),
    )


def _native_expire_replication_order(
    order_id: str,
    expiration_epoch: int,
) -> Any:
    return _native_instruction_builder("expire_replication_order")(
        order_id,
        expiration_epoch,
    )


if TYPE_CHECKING:
    from .sorafs_replication import (
        ProviderIngestCompletionAuthorityV1,
        ProviderIngestFinalizedAnchorV1,
    )

    TransactionExecutableEntry: TypeAlias = Any

    class _InstructionTypingMeta(type):
        """Expose dynamically forwarded native builders to static analyzers."""

        def __getattr__(cls, name: str) -> Any: ...

    class Instruction(Any, metaclass=_InstructionTypingMeta):
        """Typed surface of the dynamically forwarded native instruction value."""

        @classmethod
        def from_json(cls, payload: str) -> Instruction: ...

        @staticmethod
        def update_plain_conviction(
            referendum_id: str,
            owner: str,
            amount: str,
            duration_blocks: int,
        ) -> Instruction:
            """Build the exact choice-free public conviction update."""

            ...

        @staticmethod
        def cancel_asset_lock(
            escrow_id: str,
            expected_remaining_amount: str,
        ) -> Instruction:
            """Build the exact two-argument V1 cancellation instruction."""

            ...

        @staticmethod
        def issue_replication_order(
            order_id: str,
            order_payload: str,
            issued_epoch: int,
            deadline_epoch: int,
            musubi_archive: str | None = None,
        ) -> Instruction:
            """Build one canonical replication-order issue instruction."""

            ...

        @staticmethod
        def complete_replication_order(
            order_id: str,
            provider_id: str,
            completion_epoch: int,
            expected_authority: ProviderIngestCompletionAuthorityV1,
            expected_assignment_revision: int,
            finalized_anchor: ProviderIngestFinalizedAnchorV1,
        ) -> Instruction:
            """Build the exact six-field provider completion instruction."""

            ...

        @staticmethod
        def expire_replication_order(
            order_id: str,
            expiration_epoch: int,
        ) -> Instruction:
            """Build one canonical replication-order expiration instruction."""

            ...

        def to_json(self) -> str: ...

    PrivacyNativeActionBuildResultV1: TypeAlias = Any
    PrivacyExact12CapabilityManifestV1: TypeAlias = Any
    SignedTransactionEnvelope: TypeAlias = Any
    TransactionBuilder: TypeAlias = Any
else:
    TransactionExecutableEntry: TypeAlias = Union["Instruction", ContractCall]
    _NativeInstruction = _crypto.Instruction

    def _require_cancel_asset_lock_id(value: Any) -> str:
        if not isinstance(value, str):
            raise TypeError("escrow_id lock-ID preimage must be a string")
        if not value:
            raise ValueError("escrow_id lock-ID preimage must be non-empty")
        if (
            value[0].isspace()
            or value[-1].isspace()
            or value[0] == "\ufeff"
            or value[-1] == "\ufeff"
        ):
            raise ValueError(
                "escrow_id lock-ID preimage must not contain surrounding whitespace or BOM"
            )
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("escrow_id lock-ID preimage must be valid UTF-8 text") from exc
        if len(encoded) > CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1:
            raise ValueError(
                "escrow_id lock-ID preimage must be at most "
                f"{CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1} UTF-8 bytes"
            )
        return value

    class _InstructionFacadeMeta(type):
        def __getattr__(cls, name: str) -> Any:
            return getattr(_NativeInstruction, name)

        def __instancecheck__(cls, instance: object) -> bool:
            return isinstance(instance, _NativeInstruction)

    class Instruction(metaclass=_InstructionFacadeMeta):
        @staticmethod
        def update_plain_conviction(
            referendum_id: str,
            owner: str,
            amount: str,
            duration_blocks: int,
        ) -> Any:
            """Build the canonical four-field native conviction update."""

            return _native_instruction_builder("update_plain_conviction")(
                referendum_id,
                owner,
                amount,
                duration_blocks,
            )

        @staticmethod
        def cancel_asset_lock(
            escrow_id: str,
            expected_remaining_amount: str,
        ) -> Any:
            """Build V1 cancellation from an exact lock-ID preimage.

            ``escrow_id`` is bounded by
            :data:`CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1` before hashing.
            """

            return _NativeInstruction.cancel_asset_lock(
                _require_cancel_asset_lock_id(escrow_id),
                expected_remaining_amount,
            )

        @staticmethod
        def issue_replication_order(
            order_id: str,
            order_payload: str,
            issued_epoch: int,
            deadline_epoch: int,
            musubi_archive: str | None = None,
        ) -> Any:
            """Build a canonical native ``IssueReplicationOrder`` instruction."""

            from .sorafs_replication import build_issue_replication_order_instruction

            return build_issue_replication_order_instruction(
                order_id,
                order_payload,
                issued_epoch,
                deadline_epoch,
                musubi_archive,
            )

        @staticmethod
        def complete_replication_order(
            order_id: str,
            provider_id: str,
            completion_epoch: int,
            expected_authority: ProviderIngestCompletionAuthorityV1,
            expected_assignment_revision: int,
            finalized_anchor: ProviderIngestFinalizedAnchorV1,
        ) -> Any:
            """Build the exact six-field provider completion instruction."""

            from .sorafs_replication import build_complete_replication_order_instruction

            return build_complete_replication_order_instruction(
                order_id,
                provider_id,
                completion_epoch,
                expected_authority,
                expected_assignment_revision,
                finalized_anchor,
            )

        @staticmethod
        def expire_replication_order(
            order_id: str,
            expiration_epoch: int,
        ) -> Any:
            """Build a canonical native ``ExpireReplicationOrder`` instruction."""

            from .sorafs_replication import build_expire_replication_order_instruction

            return build_expire_replication_order_instruction(
                order_id,
                expiration_epoch,
            )

    PrivacyNativeActionBuildResultV1 = _crypto.PrivacyNativeActionBuildResultV1
    PrivacyExact12CapabilityManifestV1 = _crypto.PrivacyExact12CapabilityManifestV1
    SignedTransactionEnvelope = _crypto.SignedTransactionEnvelope
    TransactionBuilder = _crypto.TransactionBuilder
verify_signed_transaction_versioned = _crypto.verify_signed_transaction_versioned
DomainId = _crypto.DomainId
AccountId = _crypto.AccountId
AssetDefinitionId = _crypto.AssetDefinitionId
AssetId = _crypto.AssetId


def build_find_asset_escrow_query(
    authority: str,
    private_key: bytes,
    network_id: NetworkId,
    escrow_id: str,
) -> bytes:
    """Build a versioned Norito signed query for one native escrow."""

    return bytes(
        _crypto.build_find_asset_escrow_query(
            authority,
            private_key,
            _require_network_id(network_id),
            escrow_id,
        )
    )


def build_find_asset_escrows_by_seller_query(
    authority: str,
    private_key: bytes,
    network_id: NetworkId,
    seller: str,
) -> bytes:
    """Build a signed iterable query for escrows funded by ``seller``."""

    return bytes(
        _crypto.build_find_asset_escrows_by_seller_query(
            authority,
            private_key,
            _require_network_id(network_id),
            seller,
        )
    )


def build_find_asset_escrows_by_buyer_query(
    authority: str,
    private_key: bytes,
    network_id: NetworkId,
    buyer: str,
) -> bytes:
    """Build a signed iterable query for escrows benefiting ``buyer``."""

    return bytes(
        _crypto.build_find_asset_escrows_by_buyer_query(
            authority,
            private_key,
            _require_network_id(network_id),
            buyer,
        )
    )


def build_find_committed_transaction_query(
    authority: str,
    private_key: bytes,
    network_id: NetworkId,
    transaction_hash: str,
) -> bytes:
    """Build a signed native query for one canonical committed transaction."""

    return bytes(
        _crypto.build_find_committed_transaction_query(
            authority,
            private_key,
            _require_network_id(network_id),
            transaction_hash,
        )
    )


def build_find_block_by_hash_query(
    authority: str,
    private_key: bytes,
    network_id: NetworkId,
    block_hash: str,
) -> bytes:
    """Build a signed native query for one exact carrier block."""

    return bytes(
        _crypto.build_find_block_by_hash_query(
            authority,
            private_key,
            _require_network_id(network_id),
            block_hash,
        )
    )


def committed_transaction_carrier_block_hash(
    transaction_hash: str,
    response_bytes: bytes,
) -> str:
    """Extract the bound carrier hash from an exact native transaction response."""

    return str(
        _crypto.committed_transaction_carrier_block_hash(
            transaction_hash,
            response_bytes,
        )
    )


def verify_committed_transaction_inclusion(
    transaction_hash: str,
    transaction_response_bytes: bytes,
    *,
    native_finality_proof_chain_json: str,
    expected_network_id: NetworkId,
    expected_chain: str,
    trusted_checkpoint: bytes,
) -> Mapping[str, Any]:
    """Authenticate one exact output from an independently selected native checkpoint.

    The bounded native proof page starts at the checkpoint and extends through
    consecutive decisions. Network, chain and checkpoint must come from trusted
    configuration or a previously accepted promoted checkpoint. The returned
    ``promoted_checkpoint`` is immutable canonical bytes; retain it atomically
    only after accepting the application result. Rejections are authenticated
    too, so application policy must check ``result_ok``.
    """

    expected_network_id = _require_network_id(expected_network_id, "expected_network_id")
    for name, value in (("transaction_response_bytes", transaction_response_bytes),
                        ("trusted_checkpoint", trusted_checkpoint)):
        if type(value) is not bytes:
            raise TypeError(f"{name} must be exact immutable bytes")
    if not transaction_response_bytes or len(transaction_response_bytes) > 32 * 1024 * 1024:
        raise ValueError("transaction_response_bytes must contain 1..32 MiB")
    if not trusted_checkpoint or len(trusted_checkpoint) > 68 * 1024 * 1024:
        raise ValueError("trusted_checkpoint must contain 1..68 MiB")
    if type(native_finality_proof_chain_json) is not str:
        raise TypeError("native_finality_proof_chain_json must be a string")
    if not native_finality_proof_chain_json or len(native_finality_proof_chain_json.encode("utf-8")) > 16 * 1024 * 1024:
        raise ValueError("native_finality_proof_chain_json must contain 1..16 MiB")
    if type(expected_chain) is not str:
        raise TypeError("expected_chain must be a string")
    if not expected_chain or len(expected_chain.encode("utf-8")) > 1024:
        raise ValueError("expected_chain must contain 1..1024 UTF-8 bytes")
    native_result = _crypto.verify_committed_transaction_inclusion(
        transaction_hash, transaction_response_bytes, native_finality_proof_chain_json,
        expected_network_id, expected_chain, trusted_checkpoint,
    )
    if type(native_result) is not tuple or len(native_result) != 2:
        raise RuntimeError("native committed verifier returned malformed output")
    payload, promoted = native_result
    if type(payload) is not str or type(promoted) is not bytes or not promoted or len(promoted) > 68 * 1024 * 1024:
        raise RuntimeError("native committed verifier returned malformed checkpoint output")
    decoded = json.loads(payload)
    if not isinstance(decoded, Mapping) or "promoted_checkpoint" in decoded:
        raise RuntimeError("native committed verifier returned malformed projection")
    return {**decoded, "promoted_checkpoint": promoted}


if not TYPE_CHECKING:
    SignedTransactionEnvelope.__doc__ = (
        """Signed transaction envelope produced by the Python SDK."""
    )


_INSPECT_SORAFS_ORDERBOOK_SUBMISSION_FOR_DISCRIMINANT_V1 = getattr(
    _crypto, "inspect_sorafs_orderbook_submission_for_discriminant_v1", None
)
_VERIFY_SORAFS_ORDERBOOK_SUBMISSION_RECEIPT_V1 = getattr(
    _crypto, "verify_sorafs_orderbook_submission_receipt_v1", None
)


def signed_transaction_envelope_from_json(payload: str) -> SignedTransactionEnvelope:
    """Reconstruct a `SignedTransactionEnvelope` from its JSON representation."""

    return SignedTransactionEnvelope.from_json(payload)


def decode_transaction_receipt_json(payload: bytes) -> str:
    """Decode a Norito-framed transaction receipt into a JSON string."""

    return _crypto.decode_transaction_receipt_json(payload)


def inspect_transaction_submission_v1(
    signed_transaction_versioned: bytes,
    expected_receipt_signer: str,
) -> tuple[bytes, str]:
    """Authenticate one exact signed wire and canonically parse its pinned receipt signer."""

    if type(signed_transaction_versioned) is not bytes:
        raise TypeError("signed_transaction_versioned must be exact immutable bytes")
    if type(expected_receipt_signer) is not str or not expected_receipt_signer:
        raise TypeError("expected_receipt_signer must be exact canonical text")
    try:
        result = _crypto.inspect_transaction_submission_v1(
            signed_transaction_versioned,
            expected_receipt_signer,
        )
    except AttributeError as exc:
        raise RuntimeError(
            "iroha_native._crypto is missing inspect_transaction_submission_v1; "
            "rebuild the extension"
        ) from exc
    except Exception:
        raise ValueError("invalid transaction submission preflight") from None
    if (
        type(result) is not tuple
        or len(result) != 2
        or type(result[0]) is not bytes
        or len(result[0]) != 32
        or result[0][-1] & 1 != 1
        or result[1] != expected_receipt_signer
    ):
        raise RuntimeError("native transaction submission inspector returned malformed evidence")
    return result


def verify_transaction_submission_receipt_v1(
    receipt_norito: bytes,
    transaction_hash: str,
    expected_receipt_signer: str,
) -> str:
    """Canonically authenticate and bind one receipt to its transaction and pinned signer."""

    if type(receipt_norito) is not bytes:
        raise TypeError("receipt_norito must be exact immutable bytes")
    if not isinstance(transaction_hash, str) or not isinstance(expected_receipt_signer, str):
        raise TypeError("transaction_hash and expected_receipt_signer must be strings")
    try:
        result = _crypto.verify_transaction_submission_receipt_v1(
            receipt_norito,
            transaction_hash,
            expected_receipt_signer,
        )
    except AttributeError as exc:
        raise RuntimeError(
            "iroha_native._crypto is missing verify_transaction_submission_receipt_v1; "
            "rebuild the extension"
        ) from exc
    except Exception:
        raise ValueError("invalid transaction submission receipt") from None
    if not isinstance(result, str):
        raise RuntimeError("native transaction submission receipt verifier returned malformed JSON")
    return result


def inspect_sorafs_orderbook_submission_for_discriminant_v1(
    route: str,
    expected_network_id: NetworkId,
    expected_chain_discriminant: int,
    expected_receipt_signer: str,
    signed_transaction_versioned: bytes,
) -> Mapping[str, str]:
    """Authenticate and identify one exact route-bound orderbook transaction."""

    inspect = _INSPECT_SORAFS_ORDERBOOK_SUBMISSION_FOR_DISCRIMINANT_V1
    if not callable(inspect):
        raise RuntimeError("native crypto module lacks strict orderbook inspection")
    result = inspect(
        route,
        _require_network_id(expected_network_id),
        expected_chain_discriminant,
        expected_receipt_signer,
        signed_transaction_versioned,
    )
    if not isinstance(result, Mapping):
        raise RuntimeError("native orderbook inspector returned a malformed identity")
    return result


def verify_sorafs_orderbook_submission_receipt_v1(
    receipt_norito: bytes,
    entrypoint_hash: str,
    signed_transaction_hash: str,
    expected_receipt_signer: str,
) -> str:
    """Authenticate and bind one exact orderbook submission receipt."""

    verify_receipt = _VERIFY_SORAFS_ORDERBOOK_SUBMISSION_RECEIPT_V1
    if not callable(verify_receipt):
        raise RuntimeError("native crypto module lacks strict orderbook receipt verification")
    result = verify_receipt(
        receipt_norito,
        entrypoint_hash,
        signed_transaction_hash,
        expected_receipt_signer,
    )
    if not isinstance(result, str):
        raise RuntimeError("native orderbook receipt verifier returned malformed JSON")
    return result


def decode_zk_vk_transaction_payload(
    payload: bytes,
    network_id: NetworkId,
    expected_authority: str,
    operation: str,
) -> Mapping[str, Any]:
    """Decode and bind one canonical unsigned VK registry transaction."""

    decoded = _crypto.decode_zk_vk_transaction_payload(
        payload,
        _require_network_id(network_id),
        expected_authority,
        operation,
    )
    if not isinstance(decoded, Mapping):
        raise RuntimeError("native VK transaction decoder returned a malformed payload")
    return decoded


def _normalize_bytes(value: Any, name: str, *, expected_len: Optional[int] = None) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes")
    data = bytes(value)
    if expected_len is not None and len(data) != expected_len:
        raise ValueError(f"{name} must be exactly {expected_len} bytes (got {len(data)})")
    return data


def _decode_exact_lower_hex(value: Any, name: str, *, expected_bytes: int) -> bytes:
    expected_characters = expected_bytes * 2
    if type(value) is not str:
        raise TypeError(f"{name} must be a lowercase hexadecimal string")
    if re.fullmatch(rf"[0-9a-f]{{{expected_characters}}}", value) is None:
        raise ValueError(
            f"{name} must contain exactly {expected_characters} lowercase hexadecimal characters"
        )
    return bytes.fromhex(value)


_PROOF_BOX_MAX_ENCODED_BYTES_V1 = 64 * 1024 * 1024
_VERIFYING_KEY_ID_MAX_FIELD_BYTES = 256
_LANE_PRIVACY_MAX_MERKLE_DEPTH_V1 = 255
_PORTABLE_VERIFIER_ID_FORBIDDEN_SEPARATORS = (
    "..",
    "//",
    ":::",
    "/:",
    ":/",
    "/.",
    "./",
    ":.",
    ".:",
)


def _norito_compact_len_prefix_bytes_v1(length: int) -> int:
    """Return the canonical unsigned compact-prefix width for ``length``."""

    if length < 0:
        raise ValueError("canonical field length must be non-negative")
    return max(1, (length.bit_length() + 6) // 7)


def _proof_box_canonical_encoded_len_v1(backend: str, proof_len: int) -> int:
    """Return the exact canonical nested ``ProofBox`` payload length."""

    if proof_len < 0:
        raise ValueError("proof length must be non-negative")
    backend_len = len(backend.encode("utf-8"))
    backend_value_len = _norito_compact_len_prefix_bytes_v1(backend_len) + backend_len
    backend_field_len = _norito_compact_len_prefix_bytes_v1(backend_value_len) + backend_value_len
    # Norito V1 retains an eight-byte sequence count inside the compact-framed
    # struct member for ``Vec<u8>``.
    proof_value_len = 8 + proof_len
    proof_field_len = _norito_compact_len_prefix_bytes_v1(proof_value_len) + proof_value_len
    return backend_field_len + proof_field_len


def _proof_box_max_proof_bytes_v1(backend: str) -> int:
    """Return the largest proof whose canonical nested payload is at most 64 MiB."""

    lower = 0
    upper = _PROOF_BOX_MAX_ENCODED_BYTES_V1
    while lower < upper:
        candidate = lower + (upper - lower + 1) // 2
        if (
            _proof_box_canonical_encoded_len_v1(backend, candidate)
            <= _PROOF_BOX_MAX_ENCODED_BYTES_V1
        ):
            lower = candidate
        else:
            upper = candidate - 1
    return lower


def _require_portable_verifier_id_field(value: Any, context: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{context} must be a string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(
            f"{context} must use the bounded portable verifier-key registry grammar"
        ) from exc
    if (
        not encoded
        or len(encoded) > _VERIFYING_KEY_ID_MAX_FIELD_BYTES
        or not (
            (encoded[0:1].islower() or encoded[0:1].isdigit())
            and (encoded[-1:].islower() or encoded[-1:].isdigit())
        )
        or any(byte not in b"abcdefghijklmnopqrstuvwxyz0123456789-_/.:" for byte in encoded)
        or any(separator in value for separator in _PORTABLE_VERIFIER_ID_FORBIDDEN_SEPARATORS)
    ):
        raise ValueError(f"{context} must use the bounded portable verifier-key registry grammar")
    return value


def _normalize_lane_privacy_attachment(entry: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(entry, Mapping):
        raise TypeError("lane_privacy_attachments entries must be mappings")

    expected_fields = {
        "commitment_id",
        "leaf",
        "leaf_index",
        "audit_path",
        "proof_backend",
        "proof_bytes",
        "verifying_key_name",
    }
    unknown_fields = set(entry) - expected_fields
    if unknown_fields:
        unknown = sorted(str(field) for field in unknown_fields)[0]
        raise ValueError(
            f"lane privacy attachment contains unknown first-release field {unknown!r}"
        )

    try:
        commitment_id = entry["commitment_id"]
        leaf_index = entry["leaf_index"]
        proof_backend = _require_portable_verifier_id_field(
            entry["proof_backend"],
            "proof_backend",
        )
        proof_bytes = _normalize_bytes(entry["proof_bytes"], "proof_bytes")
        verifying_key_name = _require_portable_verifier_id_field(
            entry["verifying_key_name"],
            "verifying_key_name",
        )
        leaf = _normalize_bytes(entry["leaf"], "leaf", expected_len=32)
        raw_audit = entry["audit_path"]
    except KeyError as exc:  # pragma: no cover - defensive path
        raise KeyError(f"lane privacy attachment missing required key: {exc}") from exc

    if isinstance(commitment_id, bool) or not isinstance(commitment_id, int):
        raise TypeError("commitment_id must be an unsigned 16-bit integer")
    if commitment_id < 0 or commitment_id > 0xFFFF:
        raise ValueError("commitment_id must be an unsigned 16-bit integer")
    if isinstance(leaf_index, bool) or not isinstance(leaf_index, int):
        raise TypeError("leaf_index must be an unsigned 32-bit integer")
    if leaf_index < 0 or leaf_index > 0xFFFF_FFFF:
        raise ValueError("leaf_index must be an unsigned 32-bit integer")
    if not proof_bytes:
        raise ValueError("proof_bytes must be non-empty")
    maximum_proof_bytes = _proof_box_max_proof_bytes_v1(proof_backend)
    if len(proof_bytes) > maximum_proof_bytes:
        raise ValueError(
            f"proof_bytes exceeds the {maximum_proof_bytes}-byte limit for this backend"
        )

    if not isinstance(raw_audit, (list, tuple)):
        raise TypeError("audit_path must be a list or tuple of 32-byte siblings")
    if not 1 <= len(raw_audit) <= _LANE_PRIVACY_MAX_MERKLE_DEPTH_V1:
        raise ValueError(
            f"audit_path must contain between 1 and {_LANE_PRIVACY_MAX_MERKLE_DEPTH_V1} siblings"
        )
    if len(raw_audit) < 32 and leaf_index >= 1 << len(raw_audit):
        raise ValueError(
            f"leaf_index {leaf_index} is not representable by merkle depth {len(raw_audit)}"
        )
    audit_path: list[bytes] = []
    for idx, sibling in enumerate(raw_audit):
        if sibling is None:
            raise ValueError(f"audit_path[{idx}] must contain a sibling")
        audit_path.append(_normalize_bytes(sibling, f"audit_path[{idx}]", expected_len=32))

    return {
        "commitment_id": commitment_id,
        "leaf": leaf,
        "leaf_index": leaf_index,
        "audit_path": audit_path,
        "proof_backend": proof_backend,
        "proof_bytes": proof_bytes,
        "verifying_key_name": verifying_key_name,
    }


@dataclass(frozen=True, slots=True, repr=False)
class CryptoKeyPair:
    """Container for an `iroha_crypto` signature key pair."""

    algorithm: str
    private_key: bytes = dataclass_field(repr=False, compare=False)
    public_key: bytes = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        algorithm = normalize_crypto_algorithm(self.algorithm)
        private_key = _normalize_bytes(self.private_key, "private_key")
        public_key = _normalize_bytes(self.public_key, "public_key")
        _canonical_private_key, derived_public_key = _crypto.load_keypair(
            private_key,
            algorithm,
        )
        if bytes(derived_public_key) != public_key:
            raise ValueError("public_key does not match private_key")
        object.__setattr__(self, "algorithm", algorithm)
        object.__setattr__(self, "private_key", private_key)
        object.__setattr__(self, "public_key", public_key)

    def __repr__(self) -> str:
        """Return a useful representation without disclosing private key bytes."""

        return (
            f"{type(self).__name__}(algorithm={self.algorithm!r}, "
            f"public_key_hex={self.public_key.hex()!r})"
        )

    @classmethod
    def _from_native_result(
        cls,
        algorithm: str,
        private_key: Any,
        public_key: Any,
    ) -> "CryptoKeyPair":
        """Build from one already-validated native key operation."""

        if not isinstance(algorithm, str) or not algorithm:
            raise RuntimeError("native key operation returned an invalid algorithm")
        instance = object.__new__(cls)
        object.__setattr__(instance, "algorithm", algorithm)
        object.__setattr__(instance, "private_key", _normalize_bytes(private_key, "private_key"))
        object.__setattr__(instance, "public_key", _normalize_bytes(public_key, "public_key"))
        return instance

    @property
    def private_key_hex(self) -> str:
        """Return the private-key payload as a hex string."""

        return self.private_key.hex()

    @property
    def public_key_hex(self) -> str:
        """Return the public-key payload as a hex string."""

        return self.public_key.hex()

    @property
    def public_key_multihash(self) -> str:
        """Return the canonical bare multihash for the public key."""

        return public_key_multihash(self.algorithm, self.public_key)

    @property
    def prefixed_public_key_multihash(self) -> str:
        """Return the algorithm-prefixed multihash for the public key."""

        return public_key_multihash(self.algorithm, self.public_key, prefixed=True)

    @property
    def private_key_multihash(self) -> str:
        """Return the canonical bare multihash for the private key."""

        return private_key_multihash(self.algorithm, self.private_key)

    @property
    def prefixed_private_key_multihash(self) -> str:
        """Return the algorithm-prefixed multihash for the private key."""

        return private_key_multihash(self.algorithm, self.private_key, prefixed=True)

    def sign(self, message: bytes) -> bytes:
        """Sign ``message`` using this key pair."""

        return sign(self.algorithm, self.private_key, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify ``signature`` against ``message`` using this key pair."""

        return verify(self.algorithm, self.public_key, message, signature)

    @classmethod
    def generate(cls, algorithm: str) -> CryptoKeyPair:
        """Generate a random key pair for ``algorithm``."""

        return generate_keypair(algorithm)

    @classmethod
    def from_seed(cls, seed: bytes, algorithm: str) -> CryptoKeyPair:
        """Derive a key pair for ``algorithm`` from ``seed``."""

        return derive_keypair_from_seed(seed, algorithm)

    @classmethod
    def from_private_key(cls, algorithm: str, private_key: bytes) -> CryptoKeyPair:
        """Reconstruct a key pair for ``algorithm`` from a private-key payload."""

        return load_keypair(private_key, algorithm)

    @classmethod
    def from_private_key_multihash(cls, encoded: str) -> CryptoKeyPair:
        """Reconstruct a key pair from a private-key multihash string."""

        return load_keypair_from_multihash(encoded)


@dataclass(frozen=True, slots=True, repr=False)
class Ed25519KeyPair:
    """Container for an Ed25519 key pair."""

    private_key: bytes = dataclass_field(repr=False, compare=False)
    public_key: bytes = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        private_key = _normalize_bytes(
            self.private_key,
            "private_key",
            expected_len=ED25519_PRIVATE_KEY_LENGTH,
        )
        public_key = _normalize_bytes(
            self.public_key,
            "public_key",
            expected_len=ED25519_PUBLIC_KEY_LENGTH,
        )
        _canonical_private_key, derived_public_key = _crypto.load_ed25519_keypair(
            private_key
        )
        if bytes(derived_public_key) != public_key:
            raise ValueError("public_key does not match private_key")
        object.__setattr__(self, "private_key", private_key)
        object.__setattr__(self, "public_key", public_key)

    def __repr__(self) -> str:
        """Return a useful representation without disclosing private key bytes."""

        return f"{type(self).__name__}(public_key_hex={self.public_key.hex()!r})"

    @classmethod
    def _from_native_result(
        cls,
        private_key: Any,
        public_key: Any,
    ) -> "Ed25519KeyPair":
        """Build from one already-validated native key operation."""

        instance = object.__new__(cls)
        object.__setattr__(
            instance,
            "private_key",
            _normalize_bytes(
                private_key,
                "private_key",
                expected_len=ED25519_PRIVATE_KEY_LENGTH,
            ),
        )
        object.__setattr__(
            instance,
            "public_key",
            _normalize_bytes(
                public_key,
                "public_key",
                expected_len=ED25519_PUBLIC_KEY_LENGTH,
            ),
        )
        return instance

    @property
    def private_key_hex(self) -> str:
        """Return the private key as a hex string."""

        return self.private_key.hex()

    @property
    def public_key_hex(self) -> str:
        """Return the public key as a hex string."""

        return self.public_key.hex()

    @property
    def public_key_multihash(self) -> str:
        """Return the public key encoded with the canonical multihash prefix."""

        return ed25519_public_key_multihash(self.public_key)

    def sign(self, message: bytes) -> bytes:
        """Sign ``message`` using the private key."""

        return sign_ed25519(self.private_key, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify ``signature`` against ``message``."""

        return verify_ed25519(self.public_key, message, signature)

    @classmethod
    def from_private_key(cls, private_key: bytes) -> Ed25519KeyPair:
        """Construct a key pair from raw private key bytes."""

        return load_ed25519_keypair(private_key)

    @classmethod
    def from_private_key_hex(cls, private_key_hex: str) -> Ed25519KeyPair:
        """Construct a key pair from hex-encoded private key bytes."""

        return load_ed25519_keypair_from_hex(private_key_hex)

    def account_id(
        self, *, discriminant: int = _DEFAULT_I105_DISCRIMINANT
    ) -> str:
        """Return the canonical domainless I105 account id for the public key."""

        return ed25519_public_key_account_id(self.public_key, discriminant=discriminant)


@dataclass(frozen=True, slots=True, repr=False)
class Sm2KeyPair:
    """Container for an SM2 key pair."""

    private_key: bytes = dataclass_field(repr=False, compare=False)
    public_key: bytes = dataclass_field(repr=False)
    distid: str

    def __post_init__(self) -> None:
        private_key = _normalize_bytes(
            self.private_key,
            "private_key",
            expected_len=SM2_PRIVATE_KEY_LENGTH,
        )
        public_key = _normalize_bytes(
            self.public_key,
            "public_key",
            expected_len=SM2_PUBLIC_KEY_LENGTH,
        )
        distid = _effective_sm2_distid(self.distid)
        _canonical_private_key, derived_public_key = _crypto.load_sm2_keypair(
            private_key,
            distid,
        )
        if bytes(derived_public_key) != public_key:
            raise ValueError("public_key does not match private_key")
        object.__setattr__(self, "private_key", private_key)
        object.__setattr__(self, "public_key", public_key)
        object.__setattr__(self, "distid", distid)

    def __repr__(self) -> str:
        """Return a useful representation without disclosing private key bytes."""

        return (
            f"{type(self).__name__}(public_key_sec1_hex={self.public_key.hex()!r}, "
            f"distid={self.distid!r})"
        )

    @classmethod
    def _from_native_result(
        cls,
        private_key: Any,
        public_key: Any,
        distid: str,
    ) -> "Sm2KeyPair":
        """Build from one already-validated native key operation."""

        instance = object.__new__(cls)
        object.__setattr__(
            instance,
            "private_key",
            _normalize_bytes(
                private_key,
                "private_key",
                expected_len=SM2_PRIVATE_KEY_LENGTH,
            ),
        )
        object.__setattr__(
            instance,
            "public_key",
            _normalize_bytes(
                public_key,
                "public_key",
                expected_len=SM2_PUBLIC_KEY_LENGTH,
            ),
        )
        object.__setattr__(instance, "distid", _effective_sm2_distid(distid))
        return instance

    @property
    def private_key_hex(self) -> str:
        """Return the private key as a hex string."""

        return self.private_key.hex()

    @property
    def public_key_sec1_hex(self) -> str:
        """Return the uncompressed SEC1 public key as a hex string."""

        return self.public_key.hex()

    @property
    def public_key_multihash(self) -> str:
        """Return the canonical multihash representation of the SM2 public key."""

        return sm2_public_key_multihash(self.public_key, self.distid)

    def sign(self, message: bytes) -> bytes:
        """Sign ``message`` with the SM2 private key."""

        return sign_sm2(self.private_key, message, self.distid)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify ``signature`` against ``message`` with the SM2 public key."""

        return verify_sm2(self.public_key, message, signature, self.distid)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class ConfidentialKeyset:
    """Confidential spend/view key hierarchy derived from a 32-byte seed."""

    sk_spend: bytes = dataclass_field(repr=False)
    nk: bytes = dataclass_field(repr=False)
    ivk: bytes = dataclass_field(repr=False)
    ovk: bytes = dataclass_field(repr=False)
    fvk: bytes = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        for name in ("sk_spend", "nk", "ivk", "ovk", "fvk"):
            value = _normalize_bytes(getattr(self, name), name, expected_len=32)
            object.__setattr__(self, name, value)

    def __repr__(self) -> str:
        """Return a representation that does not disclose confidential keys."""

        return f"{type(self).__name__}(<redacted>)"

    def as_hex(self) -> dict[str, str]:
        """Return all keys hex-encoded."""

        return {
            "sk_spend": self.sk_spend_hex,
            "nk": self.nk_hex,
            "ivk": self.ivk_hex,
            "ovk": self.ovk_hex,
            "fvk": self.fvk_hex,
        }

    @property
    def sk_spend_hex(self) -> str:
        """Spend key encoded as hexadecimal."""

        return self.sk_spend.hex()

    @property
    def nk_hex(self) -> str:
        """Nullifier key encoded as hexadecimal."""

        return self.nk.hex()

    @property
    def ivk_hex(self) -> str:
        """Incoming view key encoded as hexadecimal."""

        return self.ivk.hex()

    @property
    def ovk_hex(self) -> str:
        """Outgoing view key encoded as hexadecimal."""

        return self.ovk.hex()

    @property
    def fvk_hex(self) -> str:
        """Full view key encoded as hexadecimal."""

        return self.fvk.hex()


def normalize_crypto_algorithm(algorithm: str) -> str:
    """Return the canonical `iroha_crypto` label for ``algorithm``."""

    if not isinstance(algorithm, str):
        raise TypeError("algorithm must be a string")
    algorithm = _require_exact_non_empty_string(algorithm, "algorithm")
    return str(_crypto.normalize_crypto_algorithm(algorithm))


def supported_crypto_algorithms() -> tuple[str, ...]:
    """Return canonical labels for algorithms compiled into this SDK build."""

    return SUPPORTED_CRYPTO_ALGORITHMS


def _generic_keypair(algorithm: str, private: bytes, public: bytes) -> CryptoKeyPair:
    return CryptoKeyPair._from_native_result(algorithm, private, public)


def generate_keypair(algorithm: str) -> CryptoKeyPair:
    """Generate a random key pair for any supported signature algorithm."""

    normalized = normalize_crypto_algorithm(algorithm)
    private, public = _crypto.generate_keypair(normalized)
    return _generic_keypair(normalized, private, public)


def derive_keypair_from_seed(seed: bytes, algorithm: str) -> CryptoKeyPair:
    """Derive a key pair for any supported signature algorithm from ``seed``."""

    normalized = normalize_crypto_algorithm(algorithm)
    private, public = _crypto.derive_keypair_from_seed(seed, normalized)
    return _generic_keypair(normalized, private, public)


def load_keypair(private_key: bytes, algorithm: str) -> CryptoKeyPair:
    """Reconstruct a key pair for any supported algorithm from private-key payload bytes."""

    normalized = normalize_crypto_algorithm(algorithm)
    private, public = _crypto.load_keypair(private_key, normalized)
    return _generic_keypair(normalized, private, public)


def load_keypair_from_multihash(encoded: str) -> CryptoKeyPair:
    """Reconstruct a key pair from a bare or algorithm-prefixed private-key multihash."""

    algorithm, private, public = _crypto.load_keypair_from_multihash(encoded)
    return _generic_keypair(algorithm, private, public)


def generate_ed25519_keypair() -> Ed25519KeyPair:
    """Generate a random Ed25519 key pair."""

    private, public = _crypto.generate_ed25519_keypair()
    return Ed25519KeyPair._from_native_result(private, public)


def derive_ed25519_keypair_from_seed(seed: bytes) -> Ed25519KeyPair:
    """Derive an Ed25519 key pair from ``seed``."""

    private, public = _crypto.derive_ed25519_keypair_from_seed(seed)
    return Ed25519KeyPair._from_native_result(private, public)


def load_ed25519_keypair(private_key: bytes) -> Ed25519KeyPair:
    """Reconstruct an Ed25519 key pair from raw private key bytes."""

    private, public = _crypto.load_ed25519_keypair(private_key)
    return Ed25519KeyPair._from_native_result(private, public)


def load_ed25519_keypair_from_hex(private_key_hex: str) -> Ed25519KeyPair:
    """Reconstruct an Ed25519 key pair from a hex-encoded private key."""

    return load_ed25519_keypair(
        _decode_exact_lower_hex(
            private_key_hex,
            "private_key_hex",
            expected_bytes=ED25519_PRIVATE_KEY_LENGTH,
        )
    )


def _effective_sm2_distid(distid: Optional[str]) -> str:
    if distid is None:
        return SM2_DEFAULT_DISTINGUISHED_ID
    if not isinstance(distid, str):
        raise TypeError("distid must be a string")
    cleaned = distid.strip()
    if not cleaned:
        raise ValueError("distid must not be empty")
    if cleaned != distid:
        raise ValueError("distid must not contain surrounding whitespace")
    if len(distid.encode("utf-8")) > 8_191:
        raise ValueError("distid must not exceed 8191 UTF-8 bytes")
    return distid


def generate_sm2_keypair(distid: Optional[str] = None) -> Sm2KeyPair:
    """Generate a random SM2 key pair."""

    effective_distid = _effective_sm2_distid(distid)
    private, public = _crypto.generate_sm2_keypair(distid)
    if len(private) != SM2_PRIVATE_KEY_LENGTH:
        raise RuntimeError("SM2 private key length mismatch; this is a bug")
    if len(public) != SM2_PUBLIC_KEY_LENGTH:
        raise RuntimeError("SM2 public key length mismatch; this is a bug")
    return Sm2KeyPair._from_native_result(private, public, effective_distid)


def derive_sm2_keypair_from_seed(seed: bytes, distid: Optional[str] = None) -> Sm2KeyPair:
    """Derive an SM2 key pair from ``seed``."""

    effective_distid = _effective_sm2_distid(distid)
    private, public = _crypto.derive_sm2_keypair_from_seed(seed, distid)
    if len(private) != SM2_PRIVATE_KEY_LENGTH:
        raise RuntimeError("SM2 private key length mismatch; this is a bug")
    if len(public) != SM2_PUBLIC_KEY_LENGTH:
        raise RuntimeError("SM2 public key length mismatch; this is a bug")
    return Sm2KeyPair._from_native_result(private, public, effective_distid)


def load_sm2_keypair(private_key: bytes, distid: Optional[str] = None) -> Sm2KeyPair:
    """Reconstruct an SM2 key pair from raw private key bytes."""

    effective_distid = _effective_sm2_distid(distid)
    if len(private_key) != SM2_PRIVATE_KEY_LENGTH:
        raise ValueError(
            f"private key must be {SM2_PRIVATE_KEY_LENGTH} bytes, got {len(private_key)}"
        )
    private, public = _crypto.load_sm2_keypair(private_key, distid)
    return Sm2KeyPair._from_native_result(private, public, effective_distid)


def sm2_public_key_multihash(public_key: bytes, distid: Optional[str] = None) -> str:
    """Return the canonical multihash for an SM2 public key."""

    if len(public_key) != SM2_PUBLIC_KEY_LENGTH:
        raise ValueError(f"public key must be {SM2_PUBLIC_KEY_LENGTH} bytes, got {len(public_key)}")
    return _crypto.sm2_public_key_multihash(public_key, distid)


def sign_sm2(private_key: bytes, message: bytes, distid: Optional[str] = None) -> bytes:
    """Sign ``message`` with the provided SM2 private key."""

    if len(private_key) != SM2_PRIVATE_KEY_LENGTH:
        raise ValueError(
            f"private key must be {SM2_PRIVATE_KEY_LENGTH} bytes, got {len(private_key)}"
        )
    signature = _crypto.sign_sm2(private_key, message, distid)
    if len(signature) != SM2_SIGNATURE_LENGTH:
        raise RuntimeError("SM2 signature length mismatch; this is a bug")
    return bytes(signature)


def verify_sm2(
    public_key: bytes,
    message: bytes,
    signature: bytes,
    distid: Optional[str] = None,
) -> bool:
    """Verify ``signature`` against ``message`` and the provided SM2 public key."""

    if len(public_key) != SM2_PUBLIC_KEY_LENGTH:
        raise ValueError(f"public key must be {SM2_PUBLIC_KEY_LENGTH} bytes, got {len(public_key)}")
    if len(signature) != SM2_SIGNATURE_LENGTH:
        raise ValueError(f"signature must be {SM2_SIGNATURE_LENGTH} bytes, got {len(signature)}")
    return bool(_crypto.verify_sm2(public_key, message, signature, distid))


def public_key_multihash(algorithm: str, public_key: bytes, *, prefixed: bool = False) -> str:
    """Return the canonical multihash string for a public-key payload."""

    normalized = normalize_crypto_algorithm(algorithm)
    return str(_crypto.public_key_multihash(normalized, public_key, prefixed))


def private_key_multihash(algorithm: str, private_key: bytes, *, prefixed: bool = False) -> str:
    """Return the canonical multihash string for a private-key payload."""

    normalized = normalize_crypto_algorithm(algorithm)
    return str(_crypto.private_key_multihash(normalized, private_key, prefixed))


def parse_public_key_multihash(encoded: str) -> tuple[str, bytes]:
    """Decode a bare or algorithm-prefixed public-key multihash string."""

    algorithm, public_key = _crypto.parse_public_key_multihash(encoded)
    return str(algorithm), bytes(public_key)


def parse_private_key_multihash(encoded: str) -> tuple[str, bytes]:
    """Decode a bare or algorithm-prefixed private-key multihash string."""

    algorithm, private_key = _crypto.parse_private_key_multihash(encoded)
    return str(algorithm), bytes(private_key)


def ed25519_public_key_multihash(public_key: bytes) -> str:
    """Return the canonical multihash string for an Ed25519 public key."""

    if len(public_key) != ED25519_PUBLIC_KEY_LENGTH:
        raise ValueError(
            f"public key must be {ED25519_PUBLIC_KEY_LENGTH} bytes, got {len(public_key)}"
        )
    return f"{_ED25519_MULTIHASH_PREFIX}{public_key.hex().upper()}"


def ed25519_public_key_account_id(
    public_key: bytes,
    *,
    discriminant: int = _DEFAULT_I105_DISCRIMINANT,
) -> str:
    """Return the canonical domainless I105 account id for ``public_key``."""

    address = AccountAddress.from_account(public_key=public_key)
    return address.to_i105(discriminant)


def _build_confidential_keyset(payload: Mapping[str, bytes]) -> ConfidentialKeyset:
    try:
        return ConfidentialKeyset(
            sk_spend=payload["sk_spend"],
            nk=payload["nk"],
            ivk=payload["ivk"],
            ovk=payload["ovk"],
            fvk=payload["fvk"],
        )
    except KeyError as exc:  # pragma: no cover - defensive guard
        missing = exc.args[0]
        raise RuntimeError(
            f"confidential keyset payload missing `{missing}` field; this is a bug"
        ) from exc


def derive_confidential_keyset(spend_key: bytes) -> ConfidentialKeyset:
    """Derive the confidential key hierarchy from a 32-byte spend key."""

    normalized_spend_key = _normalize_bytes(
        spend_key,
        "confidential spend key",
        expected_len=32,
    )
    raw = _crypto.derive_confidential_keyset(normalized_spend_key)
    return _build_confidential_keyset(raw)


def derive_confidential_keyset_from_hex(spend_key_hex: str) -> ConfidentialKeyset:
    """Derive the confidential key hierarchy from a hex-encoded spend key."""

    spend_key = _decode_exact_lower_hex(
        spend_key_hex,
        "confidential spend key",
        expected_bytes=32,
    )
    return derive_confidential_keyset(spend_key)


def sm2_fixture_from_seed(
    distid: str,
    seed: bytes | bytearray | memoryview | str,
    message: bytes | bytearray | memoryview | str,
) -> Dict[str, str]:
    """Return the canonical SM2 fixture values for the given seed and message."""

    if isinstance(seed, str):
        seed_bytes = seed.encode("utf-8")
    else:
        seed_bytes = bytes(seed)
    if isinstance(message, str):
        message_bytes = message.encode("utf-8")
    else:
        message_bytes = bytes(message)

    fixture = _crypto.sm2_fixture_from_seed(distid, seed_bytes, message_bytes)
    # The native layer returns a dictionary mapping to uppercase hex strings.
    return dict(fixture)


def build_signed_transaction(
    network_id: NetworkId,
    authority: str,
    private_key: bytes,
    *,
    fee_payment: Mapping[str, Any],
    instructions: Optional[Iterable[Instruction]] = None,
    entries: Optional[Iterable[TransactionExecutableEntry]] = None,
    creation_time_ms: Optional[int] = None,
    ttl_ms: Optional[int] = None,
    nonce: Optional[int] = None,
    metadata: Optional[Mapping[str, Any]] = None,
    lane_privacy_attachments: Optional[Iterable[Mapping[str, Any]]] = None,
) -> SignedTransactionEnvelope:
    """Compose and sign a transaction in one step.

    Parameters
    ----------
    network_id:
        Exact typed genesis-derived transaction network. Human-readable chain
        labels and bare hash bytes are not accepted.
    authority:
        Transaction authority account identifier (domainless encoded account
        literal: canonical I105 only).
    private_key:
        Ed25519 private key bytes aligned with `authority`.
    fee_payment:
        Required Norito JSON-compatible ``FeePaymentIntent`` mapping. The
        payer, exact sponsor revision, charge assets and maxima, and gas bound
        are included in the transaction signature.
    instructions:
        Iterable of `Instruction` instances to append using the instruction executable.
    entries:
        Ordered executable-batch entries. Supplying this argument selects batch encoding even when
        every entry is an instruction; it is mutually exclusive with ``instructions``.
    creation_time_ms:
        Optional creation timestamp in milliseconds since UNIX epoch.
    ttl_ms:
        Optional time-to-live in milliseconds.
    nonce:
        Optional non-zero nonce value.
    metadata:
        Optional mapping converted to Norito metadata.
    lane_privacy_attachments:
        Optional iterable of mappings describing Merkle lane privacy proofs. Each mapping
        must include ``commitment_id``, ``leaf`` (32-byte hash), ``leaf_index``,
        ``audit_path`` (list or tuple of 1..255 complete 32-byte siblings), ``proof_backend``,
        ``proof_bytes``, and ``verifying_key_name``.
    """

    network_id = _require_network_id(network_id)
    authority = _require_exact_non_empty_string(authority, "authority")
    if type(private_key) is not bytes:
        raise TypeError("private_key must be exact immutable bytes")
    if len(private_key) != ED25519_PRIVATE_KEY_LENGTH:
        raise ValueError(
            f"private_key must contain exactly {ED25519_PRIVATE_KEY_LENGTH} bytes"
        )
    if instructions is not None and entries is not None:
        raise ValueError("instructions and entries are mutually exclusive")
    normalized_fee_payment = _normalize_mapping_payload(fee_payment, "fee_payment")
    normalized_creation_time_ms = _optional_uint(
        creation_time_ms,
        "creation_time_ms",
        maximum=(1 << 64) - 1,
        allow_zero=True,
    )
    normalized_ttl_ms = _optional_uint(
        ttl_ms,
        "ttl_ms",
        maximum=(1 << 64) - 1,
        allow_zero=False,
    )
    normalized_nonce = _optional_uint(
        nonce,
        "nonce",
        maximum=(1 << 32) - 1,
        allow_zero=False,
    )
    normalized_metadata = (
        None
        if metadata is None
        else _normalize_mapping_payload(metadata, "metadata")
    )
    fee_payment_json = json.dumps(
        normalized_fee_payment,
        allow_nan=False,
        separators=(",", ":"),
    )
    builder = TransactionBuilder(
        network_id,
        authority,
        fee_payment_json,
    )
    if normalized_creation_time_ms is not None:
        builder.set_creation_time_ms(normalized_creation_time_ms)
    if normalized_ttl_ms is not None:
        builder.set_ttl_ms(normalized_ttl_ms)
    if normalized_nonce is not None:
        builder.set_nonce(normalized_nonce)
    if normalized_metadata is not None:
        builder.set_metadata(normalized_metadata)
    if entries is not None:
        builder.use_executable_batch()
        for index, entry in enumerate(entries):
            if isinstance(entry, ContractCall):
                builder.add_contract_call(
                    entry.contract_address,
                    entry.expected_code_hash_hex,
                    entry.entrypoint,
                    entry.arguments,
                )
            else:
                try:
                    builder.add_instruction(entry)
                except TypeError as exc:
                    raise TypeError(
                        f"entries[{index}] must be an Instruction or ContractCall"
                    ) from exc
    else:
        for instruction in instructions or ():
            builder.add_instruction(instruction)
    if lane_privacy_attachments is not None:
        for entry in lane_privacy_attachments:
            normalized = _normalize_lane_privacy_attachment(entry)
            builder.add_lane_privacy_merkle_attachment(
                normalized["commitment_id"],
                normalized["leaf"],
                normalized["leaf_index"],
                normalized["audit_path"],
                normalized["proof_backend"],
                normalized["proof_bytes"],
                normalized["verifying_key_name"],
            )
    return builder.sign(private_key)


def sign(algorithm: str, private_key: bytes, message: bytes) -> bytes:
    """Return a signature for ``message`` using any supported algorithm."""

    normalized = normalize_crypto_algorithm(algorithm)
    return bytes(_crypto.sign(normalized, private_key, message))


def verify(algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a signature for any supported algorithm."""

    normalized = normalize_crypto_algorithm(algorithm)
    return bool(_crypto.verify(normalized, public_key, message, signature))


def sign_ed25519(private_key: bytes, message: bytes) -> bytes:
    """Return the Ed25519 signature for ``message``."""

    return _crypto.sign_ed25519(private_key, message)


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature."""

    return _crypto.verify_ed25519(public_key, message, signature)


def hash_blake2b_32(data: bytes) -> bytes:
    """Compute the canonical Iroha Blake2b-256 hash for ``data``."""

    return _crypto.hash_blake2b_32(data)


_U128_MAX: Final[int] = (1 << 128) - 1


def _normalize_u128_literal(value: int | str, name: str) -> str:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a whole-number u128 string")
    if isinstance(value, int):
        amount = value
    elif isinstance(value, str):
        normalized = value.strip()
        if not normalized.isdecimal():
            raise ValueError(f"{name} must be a whole-number u128 string")
        amount = int(normalized, 10)
    else:
        raise TypeError(f"{name} must be a whole-number u128 string")
    if amount < 0 or amount > _U128_MAX:
        raise ValueError(f"{name} must be a whole-number u128 string")
    return str(amount)


def _require_exact_non_empty_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{context} must be a non-empty string")
    if value.strip() != value:
        raise ValueError(f"{context} must not contain surrounding whitespace")
    return value


def _confidential_path_hex(value: Any, name: str) -> str:
    data = bytes(value)
    if len(data) != 32:
        raise RuntimeError(f"{name} must be 32 bytes, got {len(data)}")
    return data.hex()


def _confidential_path_list_hex(value: Any, name: str) -> list[str]:
    if not isinstance(value, list):
        raise RuntimeError(f"{name} must be a list")
    return [_confidential_path_hex(item, f"{name}[{index}]") for index, item in enumerate(value)]


def _confidential_merkle_path_result(result: Any, context: str) -> Dict[str, Any]:
    if not isinstance(result, dict):
        raise RuntimeError(f"{context} returned a non-object payload")
    leaf_index = result.get("leaf_index")
    if isinstance(leaf_index, bool) or not isinstance(leaf_index, int) or leaf_index < 0:
        raise RuntimeError(f"{context} returned an invalid leaf_index")
    directions_raw = result.get("directions")
    if not isinstance(directions_raw, list):
        raise RuntimeError(f"{context} returned invalid directions")
    directions = []
    for index, item in enumerate(directions_raw):
        if item not in (0, 1):
            raise RuntimeError(f"{context} directions[{index}] must be 0 or 1")
        directions.append(int(item))
    return {
        "leaf_index": leaf_index,
        "commitment": _confidential_path_hex(result.get("commitment"), f"{context}.commitment"),
        "siblings": _confidential_path_list_hex(result.get("siblings"), f"{context}.siblings"),
        "directions": directions,
        "witness_nodes": _confidential_path_list_hex(
            result.get("witness_nodes"),
            f"{context}.witness_nodes",
        ),
        "root": _confidential_path_hex(result.get("root"), f"{context}.root"),
    }


def compute_confidential_root_v2(
    tree_commitments: Iterable[bytes | bytearray | memoryview | str],
) -> bytes:
    """Compute the canonical confidential-transfer v2 tree root."""

    if not hasattr(_crypto, "compute_confidential_root_v2"):
        raise RuntimeError(
            "iroha_native._crypto is missing confidential root v2 support; rebuild the extension"
        )
    result = _crypto.compute_confidential_root_v2(list(tree_commitments))
    root = bytes(result)
    if len(root) != 32:
        raise RuntimeError("confidential root v2 returned a non-32-byte root")
    return root


def derive_confidential_next_zero_path_v2(
    *,
    previous_leaf_commitment: bytes | bytearray | memoryview | str,
    previous_leaf_index: int,
    previous_path: Mapping[str, Any],
    root_hint: bytes | bytearray | memoryview | str,
) -> Dict[str, Any]:
    """Derive the padded zero-leaf path immediately after the latest commitment."""

    if not hasattr(_crypto, "derive_confidential_next_zero_path_v2"):
        raise RuntimeError(
            "iroha_native._crypto is missing confidential next-zero path support; rebuild the extension"
        )
    if isinstance(previous_leaf_index, bool) or not isinstance(previous_leaf_index, int):
        raise TypeError("previous_leaf_index must be a non-negative integer")
    if previous_leaf_index < 0:
        raise ValueError("previous_leaf_index must be a non-negative integer")
    result = _crypto.derive_confidential_next_zero_path_v2(
        previous_leaf_commitment,
        previous_leaf_index,
        dict(previous_path),
        root_hint,
    )
    return _confidential_merkle_path_result(result, "confidential next-zero path")


def default_confidential_diversifier_v2() -> bytes:
    """Return the native canonical diversifier used by private redemption change."""
    if not hasattr(_crypto, "default_confidential_diversifier_v2"):
        raise RuntimeError("rebuild the native extension for the confidential change diversifier")
    value = bytes(_crypto.default_confidential_diversifier_v2())
    if len(value) != 32:
        raise RuntimeError("native default diversifier must be 32 bytes")
    return value


def derive_confidential_diversifier_v2(
    seed: bytes | str,
) -> bytes:
    """Derive a note diversifier from bytes or hex, bounded to 1 MiB decoded."""

    if not hasattr(_crypto, "derive_confidential_diversifier_v2"):
        raise RuntimeError(
            "iroha_native._crypto is missing confidential diversifier v2 support; rebuild the extension"
        )
    result = _crypto.derive_confidential_diversifier_v2(seed)
    diversifier = bytes(result)
    if len(diversifier) != 32:
        raise RuntimeError("confidential diversifier v2 returned non-32-byte output")
    return diversifier


def derive_confidential_owner_tag_v2(
    spend_key: bytes | str,
    diversifier: bytes | str,
) -> bytes:
    """Derive an owner tag from bytes or hex; the decoded key is at most 1 MiB."""

    if not hasattr(_crypto, "derive_confidential_owner_tag_v2"):
        raise RuntimeError(
            "iroha_native._crypto is missing confidential owner tag v2 support; rebuild the extension"
        )
    result = _crypto.derive_confidential_owner_tag_v2(spend_key, diversifier)
    owner_tag = bytes(result)
    if len(owner_tag) != 32:
        raise RuntimeError("confidential owner tag v2 returned non-32-byte output")
    return owner_tag


def derive_confidential_note_v2(
    asset_definition_id: str,
    amount: int,
    rho: bytes | str,
    owner_tag: bytes | str,
) -> bytes:
    """Derive a note commitment from two exact 32-byte words (bytes or hex)."""

    if not hasattr(_crypto, "derive_confidential_note_v2"):
        raise RuntimeError(
            "iroha_native._crypto is missing confidential note v2 support; rebuild the extension"
        )
    result = _crypto.derive_confidential_note_v2(
        asset_definition_id,
        amount,
        rho,
        owner_tag,
    )
    note_commitment = bytes(result)
    if len(note_commitment) != 32:
        raise RuntimeError("confidential note v2 returned non-32-byte output")
    return note_commitment


def confidential_transfer_v2_verifying_key_registration_payload_v1() -> Dict[str, Any]:
    """Build the canonical active confidential transfer v2 verifier-key payload."""

    method = "confidential_transfer_v2_verifying_key_registration_payload_v1"
    if not hasattr(_crypto, method):
        raise RuntimeError(
            "iroha_native._crypto is missing confidential transfer v2 verifier-key support; "
            "rebuild the extension"
        )
    payload = getattr(_crypto, method)()
    if not isinstance(payload, Mapping):
        raise RuntimeError(
            "confidential transfer v2 verifier-key builder returned a non-object payload"
        )
    return dict(payload)


def confidential_unshield_v3_verifying_key_registration_payload_v1() -> Dict[str, Any]:
    """Build the canonical active confidential unshield v3 verifier-key payload."""

    method = "confidential_unshield_v3_verifying_key_registration_payload_v1"
    if not hasattr(_crypto, method):
        raise RuntimeError(
            "iroha_native._crypto is missing confidential unshield v3 verifier-key support; "
            "rebuild the extension"
        )
    payload = getattr(_crypto, method)()
    if not isinstance(payload, Mapping):
        raise RuntimeError(
            "confidential unshield v3 verifier-key builder returned a non-object payload"
        )
    return dict(payload)


def _privacy_unsigned_byte_view(
    value: object,
    *,
    bytes_like_message: str,
    typed_message: str,
) -> memoryview:
    try:
        view = memoryview(cast(Any, value))
    except TypeError as exc:
        raise TypeError(bytes_like_message) from exc
    if view.format != "B" or view.itemsize != 1:
        raise TypeError(typed_message)
    return view


def _privacy_output_archive(module: object, operation: str, result: object) -> bytes:
    if result is None:
        raise RuntimeError(f"native {operation} returned no output")
    if isinstance(result, str):
        raise RuntimeError(f"native {operation} returned text instead of Norito V1 bytes")
    view = _privacy_unsigned_byte_view(
        result,
        bytes_like_message=f"native {operation} returned non-byte output",
        typed_message=f"native {operation} output must use unsigned byte elements",
    )
    if view.nbytes == 0:
        raise RuntimeError(f"native {operation} returned empty output")
    if view.nbytes > PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES:
        raise RuntimeError(f"native {operation} returned oversized output")
    archive = view.tobytes()
    if not archive:
        raise RuntimeError(f"native {operation} returned empty output")
    validation_status = _invoke_privacy_compiled_profile_catalog_validator(
        module, archive
    )
    if (
        validation_status
        != PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1["VALID"]
    ):
        raise RuntimeError(
            f"native {operation} returned an invalid typed privacy compiled-profile catalog"
        )
    return archive


def _clear_privacy_native_output(result: object) -> None:
    if result is None or isinstance(result, str):
        return
    try:
        view = _privacy_unsigned_byte_view(
            result,
            bytes_like_message="native privacy output must be bytes-like",
            typed_message="native privacy output must use unsigned byte elements",
        )
    except TypeError:
        return
    if view.readonly or view.nbytes == 0:
        return
    try:
        view[:] = b"\x00" * view.nbytes
    except (TypeError, ValueError, BufferError):
        return


_PRIVACY_BRIDGE_ABI_VERSION_METHOD: Final[str] = "privacy_bridge_abi_version"
_PRIVACY_COMPILED_PROFILE_CATALOG_METHOD: Final[str] = (
    "privacy_compiled_profile_catalog_v1"
)
_PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATOR_METHOD: Final[str] = (
    "privacy_validate_compiled_profile_catalog_v1"
)
_PRIVACY_EXACT12_CAPABILITY_MANIFEST_METHOD: Final[str] = (
    "privacy_exact12_capability_manifest_v1"
)
_PRIVACY_EXACT12_CAPABILITY_MANIFEST_VALIDATOR_METHOD: Final[str] = (
    "privacy_validate_exact12_capability_manifest_v1"
)


def _privacy_bridge_abi_version(module: object) -> int | None:
    method = getattr(module, _PRIVACY_BRIDGE_ABI_VERSION_METHOD, None)
    if not callable(method):
        return None
    try:
        version = method()
    except Exception:
        return None
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version < 0
        or version > _PRIVACY_MAX_BRIDGE_ABI_VERSION
    ):
        return None
    return version


def _has_privacy_bridge_abi(module: object) -> bool:
    version = _privacy_bridge_abi_version(module)
    return version == PRIVACY_REQUIRED_BRIDGE_ABI_VERSION


def _privacy_compiled_profile_catalog_validator(module: object):
    if not _has_privacy_bridge_abi(module):
        raise RuntimeError(
            "privacy compiled-profile catalogs require native bridge ABI "
            f"{PRIVACY_REQUIRED_BRIDGE_ABI_VERSION}"
        )
    method = getattr(
        module, _PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATOR_METHOD, None
    )
    if not callable(method):
        raise RuntimeError(
            "iroha_native._crypto is missing "
            "privacy_validate_compiled_profile_catalog_v1; "
            "rebuild the extension"
        )
    return method


def _invoke_privacy_compiled_profile_catalog_validator(
    module: object, archive: bytes
) -> int:
    try:
        status = _privacy_compiled_profile_catalog_validator(module)(archive)
    except Exception:
        raise RuntimeError(
            "native privacy compiled-profile catalog validation failed"
        ) from None
    if (
        isinstance(status, bool)
        or not isinstance(status, int)
        or status
        not in PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1.values()
    ):
        raise RuntimeError(
            "native privacy compiled-profile catalog validation returned invalid status"
        )
    return status


def _privacy_compiled_profile_catalog_method(module: object):
    if not _has_privacy_bridge_abi(module):
        raise RuntimeError(
            "privacy compiled-profile catalogs require native bridge ABI "
            f"{PRIVACY_REQUIRED_BRIDGE_ABI_VERSION}"
        )
    method = getattr(module, _PRIVACY_COMPILED_PROFILE_CATALOG_METHOD, None)
    if not callable(method):
        raise RuntimeError(
            "iroha_native._crypto is missing privacy_compiled_profile_catalog_v1; "
            "rebuild the extension"
        )
    return method


def _privacy_native_probe_returns_bytes(module: object) -> bool:
    result: object | None = None
    try:
        result = _privacy_compiled_profile_catalog_method(module)()
        _privacy_output_archive(
            module, _PRIVACY_COMPILED_PROFILE_CATALOG_METHOD, result
        )
        return True
    except Exception:
        return False
    finally:
        _clear_privacy_native_output(result)


def _invoke_privacy_compiled_profile_catalog_native() -> object:
    try:
        return _privacy_compiled_profile_catalog_method(_crypto)()
    except Exception:
        raise RuntimeError(
            "native privacy_compiled_profile_catalog_v1 failed"
        ) from None


def privacy_bridge_abi_version() -> int:
    """Return the native bridge ABI version required by privacy build metadata."""

    version = _privacy_bridge_abi_version(_crypto)
    if version is None:
        raise RuntimeError(
            "privacy compiled-profile catalogs require native bridge ABI "
            f"{PRIVACY_REQUIRED_BRIDGE_ABI_VERSION}"
        )
    return version


def is_privacy_native_available() -> bool:
    """Return whether the typed local compiled-profile catalog bridge is available."""

    return _privacy_native_probe_returns_bytes(_crypto)


def privacy_compiled_profile_catalog_v1() -> bytes:
    """Return this binary's canonical Norito V1 local compiled-profile catalog.

    This archive has no committed height, governance activation, or readiness
    state. Use the client's authoritative Exact12 capability query for a fresh
    snapshot from live Torii.
    """

    return _privacy_output_archive(
        _crypto,
        _PRIVACY_COMPILED_PROFILE_CATALOG_METHOD,
        _invoke_privacy_compiled_profile_catalog_native(),
    )


def _privacy_exact12_capability_manifest_archive(
    archive: bytes | bytearray | memoryview,
) -> bytes:
    if not isinstance(archive, (bytes, bytearray, memoryview)):
        raise TypeError("Exact12 capability manifest archive must be bytes-like")
    canonical = bytes(archive)
    if not canonical:
        raise ValueError("Exact12 capability manifest archive must be non-empty")
    if len(canonical) > PRIVACY_EXACT12_CAPABILITY_MANIFEST_ARCHIVE_MAX_BYTES_V1:
        raise ValueError("Exact12 capability manifest archive exceeds 262144 bytes")
    return canonical


def privacy_validate_exact12_capability_manifest_v1(
    archive: bytes | bytearray | memoryview,
) -> int:
    """Return the native status for one untrusted canonical manifest archive."""

    canonical = _privacy_exact12_capability_manifest_archive(archive)
    if not _has_privacy_bridge_abi(_crypto):
        raise RuntimeError(
            "Exact12 capability manifests require native bridge ABI "
            f"{PRIVACY_REQUIRED_BRIDGE_ABI_VERSION}"
        )
    validator = getattr(
        _crypto,
        _PRIVACY_EXACT12_CAPABILITY_MANIFEST_VALIDATOR_METHOD,
        None,
    )
    if not callable(validator):
        raise RuntimeError(
            "iroha_native._crypto is missing "
            "privacy_validate_exact12_capability_manifest_v1; rebuild the extension"
        )
    try:
        status = validator(canonical)
    except Exception:
        raise RuntimeError("native Exact12 capability manifest validation failed") from None
    if (
        isinstance(status, bool)
        or not isinstance(status, int)
        or status
        not in PRIVACY_EXACT12_CAPABILITY_MANIFEST_VALIDATION_STATUS_V1.values()
    ):
        raise RuntimeError(
            "native Exact12 capability manifest validator returned an invalid status"
        )
    return status


def privacy_exact12_capability_manifest_v1(
    archive: bytes | bytearray | memoryview,
) -> PrivacyExact12CapabilityManifestV1:
    """Inspect one native-validated archive without granting transaction admission.

    The native object retains and re-exposes the byte-identical canonical
    archive. Admission requires a fresh authenticated fetch through the
    configured authenticated Torii manifest transport owner.
    """

    canonical = _privacy_exact12_capability_manifest_archive(archive)
    status = privacy_validate_exact12_capability_manifest_v1(canonical)
    if status != PRIVACY_EXACT12_CAPABILITY_MANIFEST_VALIDATION_STATUS_V1["VALID"]:
        raise ValueError(
            "invalid canonical Exact12 capability manifest archive "
            f"(native status {status})"
        )
    decoder = getattr(_crypto, _PRIVACY_EXACT12_CAPABILITY_MANIFEST_METHOD, None)
    if not callable(decoder):
        raise RuntimeError(
            "iroha_native._crypto is missing privacy_exact12_capability_manifest_v1; "
            "rebuild the extension"
        )
    try:
        manifest = decoder(canonical)
    except Exception:
        raise ValueError("native Exact12 capability manifest decode failed") from None
    returned = getattr(manifest, "canonical_archive", None)
    if not isinstance(returned, (bytes, bytearray, memoryview)):
        raise RuntimeError("native Exact12 capability manifest omitted its canonical archive")
    if bytes(returned) != canonical:
        raise RuntimeError("native Exact12 capability manifest changed the Torii archive bytes")
    return manifest


def _fetch_privacy_exact12_capability_manifest_v1(
    client: object, canonical_auth: object
) -> PrivacyExact12CapabilityManifestV1:
    """Enter the native fetch boundary; it accepts no caller-supplied archive."""
    fetch = getattr(_crypto, "_privacy_fetch_exact12_capability_manifest_v1", None)
    if not callable(fetch):
        raise RuntimeError("native authenticated Exact12 capability fetch is unavailable")
    return fetch(client, canonical_auth)


def canonical_genesis_header_hash_v1(
    framed_signed_genesis: bytes | bytearray | memoryview,
) -> bytes:
    """Return the header hash of one exact canonical framed signed genesis.

    Authentication and root selection remain the caller's responsibility. The
    native boundary rejects malformed, non-canonical, non-genesis, and
    oversized block wires before returning a hash.
    """

    if not isinstance(framed_signed_genesis, (bytes, bytearray, memoryview)):
        raise TypeError("framed_signed_genesis must be bytes-like")
    try:
        result = _crypto.canonical_genesis_header_hash_v1(bytes(framed_signed_genesis))
    except AttributeError as exc:
        raise RuntimeError(
            "iroha_native._crypto is missing canonical_genesis_header_hash_v1; "
            "rebuild the extension"
        ) from exc
    except Exception:
        raise ValueError("invalid canonical framed signed genesis") from None
    if not isinstance(result, bytes) or len(result) != 32 or result == bytes(32):
        raise RuntimeError("native canonical genesis hash returned invalid bytes")
    return result


def canonical_signed_transaction_hash_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
) -> bytes:
    """Authenticate one exact current signed wire and recompute its chain hash."""

    if not isinstance(
        signed_transaction_versioned,
        (bytes, bytearray, memoryview),
    ):
        raise TypeError("signed_transaction_versioned must be bytes-like")
    try:
        result = _crypto.canonical_signed_transaction_hash_v1(bytes(signed_transaction_versioned))
    except AttributeError as exc:
        raise RuntimeError(
            "iroha_native._crypto is missing canonical_signed_transaction_hash_v1; "
            "rebuild the extension"
        ) from exc
    except Exception:
        raise ValueError("invalid canonical signed transaction") from None
    if not isinstance(result, bytes) or len(result) != 32:
        raise RuntimeError("native canonical signed transaction hash returned invalid bytes")
    return result


def signed_transaction_envelope_from_versioned_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
    network_id: NetworkId,
) -> SignedTransactionEnvelope:
    """Reconstruct an authenticated envelope bound to one exact NetworkId."""

    if not isinstance(
        signed_transaction_versioned,
        (bytes, bytearray, memoryview),
    ):
        raise TypeError("signed_transaction_versioned must be bytes-like")
    network_id = _require_network_id(network_id)
    try:
        result = _crypto.signed_transaction_envelope_from_versioned_v1(
            bytes(signed_transaction_versioned),
            network_id,
        )
    except AttributeError as exc:
        raise RuntimeError(
            "iroha_native._crypto is missing "
            "signed_transaction_envelope_from_versioned_v1; rebuild the extension"
        ) from exc
    except Exception:
        raise ValueError("invalid canonical signed transaction") from None
    if not _is_native_crypto_instance(result, "SignedTransactionEnvelope"):
        raise RuntimeError("native signed transaction envelope returned an invalid result")
    return result


def _is_native_crypto_instance(value: object, type_name: str) -> bool:
    """Return whether ``value`` has the named concrete PyO3 extension type."""

    native_type = getattr(_crypto, type_name, None)
    return isinstance(native_type, type) and isinstance(value, native_type)


def account_faucet_claim_hash_v1(
    account_id: str,
    *,
    pow_anchor_height: int,
    pow_nonce_hex: str,
) -> str:
    """Return the canonical solved-claim digest for binding.semantic_hash_hex.

    Call after ``solve_account_faucet_pow`` and before constructing the binding
    passed to ``prepare_account_faucet``. The native helper validates the exact
    account, positive u64 anchor and 1..32-byte lowercase nonce, then hashes the
    canonical Norito claim with ``iroha:accounts:faucet:claim:v1\0``. It does not
    assert that the nonce satisfies the faucet's current proof-of-work policy.
    """

    if type(account_id) is not str:
        raise TypeError("account_id must be an exact canonical account string")
    if type(pow_anchor_height) is not int or not 0 < pow_anchor_height < 1 << 64:
        raise ValueError("pow_anchor_height must be a positive u64")
    if type(pow_nonce_hex) is not str:
        raise TypeError("pow_nonce_hex must be a string")
    if re.fullmatch(r"(?:[0-9a-f]{2}){1,32}", pow_nonce_hex) is None:
        raise ValueError("pow_nonce_hex must be 1..32 bytes of canonical lowercase hexadecimal")
    return str(_crypto.account_faucet_claim_hash_v1(account_id, pow_anchor_height, pow_nonce_hex))


def verify_prepared_transaction_context_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
    network_id: NetworkId,
    expected_authority: str,
    binding_json: str,
    operation: str,
    semantic_hash_hex: str,
    fee_payment_json: str,
    operation_context_json: str,
) -> SignedTransactionEnvelope:
    """Authenticate one prepared transaction's exact V1 public and semantic context."""

    if not isinstance(
        signed_transaction_versioned,
        (bytes, bytearray, memoryview),
    ):
        raise TypeError("signed_transaction_versioned must be bytes-like")
    network_id = _require_network_id(network_id)
    try:
        result = _crypto.verify_prepared_transaction_context_v1(
            bytes(signed_transaction_versioned),
            network_id,
            expected_authority,
            binding_json,
            operation,
            semantic_hash_hex,
            fee_payment_json,
            operation_context_json,
        )
    except AttributeError as exc:
        raise RuntimeError(
            "iroha_native._crypto is missing verify_prepared_transaction_context_v1; "
            "rebuild the extension"
        ) from exc
    except Exception:
        raise ValueError("invalid prepared transaction context") from None
    if not _is_native_crypto_instance(result, "SignedTransactionEnvelope"):
        raise RuntimeError("native prepared transaction verifier returned an invalid result")
    return result


def verify_account_onboarding_receipt_v1(
    receipt_json: str,
    network_id: NetworkId,
    expected_authority: str,
    expected_account_id: str,
    expected_alias: str,
    expected_permissions_json: str,
) -> str:
    """Authenticate an exact canonical V1 onboarding receipt and complete request."""

    if not isinstance(receipt_json, str):
        raise TypeError("receipt_json must be a string")
    network_id = _require_network_id(network_id)
    try:
        result = _crypto.verify_account_onboarding_receipt_v1(
            receipt_json,
            network_id,
            expected_authority,
            expected_account_id,
            expected_alias,
            expected_permissions_json,
        )
    except AttributeError as exc:
        raise RuntimeError(
            "iroha_native._crypto is missing verify_account_onboarding_receipt_v1; "
            "rebuild the extension"
        ) from exc
    except Exception:
        raise ValueError("invalid account onboarding receipt") from None
    if not isinstance(result, str) or re.fullmatch(r"[0-9a-f]{64}", result) is None:
        raise RuntimeError("native onboarding receipt verifier returned an invalid hash")
    return result


def inspect_privacy_exact12_action_driver_transaction_context_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
    candidate_binding_sha256: bytes | bytearray | memoryview,
    request_id: bytes | bytearray | memoryview,
    network_id: NetworkId,
    creation_time_millis: int,
    ttl_millis: int,
    nonce: int,
) -> Mapping[str, Any]:
    """Authenticate one qualification action's exact signed public context.

    The Rust boundary derives the expected signer internally from the candidate
    and request identities. It returns only authenticated public identity; no
    signing key or witness material crosses the extension boundary.
    """

    byte_inputs = (
        (signed_transaction_versioned, "signed_transaction_versioned", None),
        (candidate_binding_sha256, "candidate_binding_sha256", 32),
        (request_id, "request_id", 32),
    )
    normalized: list[bytes] = []
    for value, field, expected_length in byte_inputs:
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise TypeError(f"{field} must be bytes-like")
        encoded = bytes(value)
        if expected_length is not None and len(encoded) != expected_length:
            raise ValueError(f"{field} must be exactly {expected_length} bytes")
        normalized.append(encoded)
    network_id = _require_network_id(network_id)
    if (
        not isinstance(creation_time_millis, int)
        or isinstance(creation_time_millis, bool)
        or not isinstance(ttl_millis, int)
        or isinstance(ttl_millis, bool)
        or not isinstance(nonce, int)
        or isinstance(nonce, bool)
    ):
        raise TypeError("transaction time fields and nonce must be integers")
    if not 1 <= creation_time_millis <= 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError("creation_time_millis must be one nonzero u64")
    if not 1 <= ttl_millis <= 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError("ttl_millis must be one nonzero u64")
    if not 1 <= nonce <= 0xFFFF_FFFF:
        raise ValueError("nonce must be one nonzero u32")
    try:
        result = _crypto.inspect_privacy_exact12_action_driver_transaction_context_v1(
            normalized[0],
            normalized[1],
            normalized[2],
            network_id,
            creation_time_millis,
            ttl_millis,
            nonce,
        )
    except AttributeError as exc:
        raise RuntimeError(
            "iroha_native._crypto is missing the Exact12 action-driver context inspector; "
            "rebuild the extension"
        ) from exc
    except Exception:
        raise ValueError("invalid Exact12 action-driver transaction context") from None
    if not isinstance(result, Mapping):
        raise RuntimeError("native Exact12 action-driver context inspector returned malformed data")
    return result


def privacy_vega_device_authentication_digest_v1(
    network_id: NetworkId,
    transaction_intent_digest: bytes | bytearray | memoryview,
    issuer_id: bytes | bytearray | memoryview,
    issuer_record_epoch: int,
    issuer_record_digest: bytes | bytearray | memoryview,
    issuer_public_key: bytes | bytearray | memoryview,
    presentation_year: int,
    presentation_month: int,
    presentation_day: int,
    minimum_age_years: int,
    reader_challenge: bytes | bytearray | memoryview,
    session_transcript_digest: bytes | bytearray | memoryview,
) -> bytes:
    """Request Vega ``H_dev`` for an explicit prepared transaction intent.

    This public entry point fails closed while the binary has no exact
    governance-available compiled Vega profile. In that state, otherwise-valid
    inputs raise :class:`RuntimeError`; candidate or placeholder profile material
    is never used. If the compiled profile becomes available, the native
    derivation fixes the ISO 18013-5 document profile, action index, governed
    Vega artifacts, exact NetworkId, date, threshold, reader challenge, session
    transcript, and canonical nonzero transaction intent. This helper handles
    public binding data only; generic Vega construction and every
    credential-bearing operation must use :class:`PrivacyWalletWorkerControllerV1`.
    """

    network_id = _require_network_id(network_id)
    byte_inputs = (
        (transaction_intent_digest, "transaction_intent_digest"),
        (issuer_id, "issuer_id"),
        (issuer_record_digest, "issuer_record_digest"),
        (issuer_public_key, "issuer_public_key"),
        (reader_challenge, "reader_challenge"),
        (session_transcript_digest, "session_transcript_digest"),
    )
    for value, field in byte_inputs:
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise TypeError(f"{field} must be bytes-like")
    try:
        result = _crypto.privacy_vega_device_authentication_digest_v1(
            network_id,
            bytes(transaction_intent_digest),
            bytes(issuer_id),
            issuer_record_epoch,
            bytes(issuer_record_digest),
            bytes(issuer_public_key),
            presentation_year,
            presentation_month,
            presentation_day,
            minimum_age_years,
            bytes(reader_challenge),
            bytes(session_transcript_digest),
        )
    except AttributeError as exc:
        raise RuntimeError(
            "iroha_native._crypto is missing "
            "privacy_vega_device_authentication_digest_v1; rebuild the extension"
        ) from exc
    except RuntimeError:
        # Compiled-profile/engine unavailability is a public fail-closed state,
        # not an invalid statement. Preserve the native exception and detail.
        raise
    except Exception:
        raise ValueError("invalid Vega device-authentication statement") from None
    if not isinstance(result, bytes) or len(result) != 32 or result == bytes(32):
        raise RuntimeError("native Vega device-authentication derivation returned invalid bytes")
    return result


def inspect_signed_privacy_zk_ace_transfer_action_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
) -> dict[str, Any]:
    """Authenticate and inspect one exact native ZK-ACE transfer action."""

    if not isinstance(
        signed_transaction_versioned,
        (bytes, bytearray, memoryview),
    ):
        raise TypeError("signed_transaction_versioned must be bytes-like")
    try:
        result = _crypto.inspect_signed_privacy_zk_ace_transfer_action_v1(
            bytes(signed_transaction_versioned)
        )
    except AttributeError as exc:
        raise RuntimeError(
            "iroha_native._crypto is missing "
            "inspect_signed_privacy_zk_ace_transfer_action_v1; rebuild the extension"
        ) from exc
    except Exception:
        raise ValueError("invalid canonical signed ZK-ACE transfer action") from None
    if type(result) is not dict:
        raise RuntimeError("native ZK-ACE transfer action inspection returned an invalid result")
    return result


def inspect_signed_privacy_jindo_action_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
) -> dict[str, Any]:
    """Authenticate and inspect public metadata from one exact Jindo action."""

    if not isinstance(
        signed_transaction_versioned,
        (bytes, bytearray, memoryview),
    ):
        raise TypeError("signed_transaction_versioned must be bytes-like")
    try:
        result = _crypto.inspect_signed_privacy_jindo_action_v1(bytes(signed_transaction_versioned))
    except AttributeError as exc:
        raise RuntimeError(
            "iroha_native._crypto is missing "
            "inspect_signed_privacy_jindo_action_v1; rebuild the extension"
        ) from exc
    except Exception:
        raise ValueError("invalid canonical signed Jindo action") from None
    if type(result) is not dict:
        raise RuntimeError("native Jindo action inspection returned an invalid result")
    return result


def inspect_signed_privacy_verange_action_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
) -> dict[str, Any]:
    """Authenticate and inspect public metadata from one exact VeRange action."""

    if not isinstance(
        signed_transaction_versioned,
        (bytes, bytearray, memoryview),
    ):
        raise TypeError("signed_transaction_versioned must be bytes-like")
    try:
        result = _crypto.inspect_signed_privacy_verange_action_v1(
            bytes(signed_transaction_versioned)
        )
    except AttributeError as exc:
        raise RuntimeError(
            "iroha_native._crypto is missing "
            "inspect_signed_privacy_verange_action_v1; rebuild the extension"
        ) from exc
    except Exception:
        raise ValueError("invalid canonical signed VeRange action") from None
    if type(result) is not dict:
        raise RuntimeError("native VeRange action inspection returned an invalid result")
    return result


def inspect_signed_privacy_vega_action_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
) -> dict[str, Any]:
    """Authenticate and inspect public metadata from one exact Vega action."""

    if not isinstance(
        signed_transaction_versioned,
        (bytes, bytearray, memoryview),
    ):
        raise TypeError("signed_transaction_versioned must be bytes-like")
    try:
        result = _crypto.inspect_signed_privacy_vega_action_v1(bytes(signed_transaction_versioned))
    except AttributeError as exc:
        raise RuntimeError(
            "iroha_native._crypto is missing "
            "inspect_signed_privacy_vega_action_v1; rebuild the extension"
        ) from exc
    except Exception:
        raise ValueError("invalid canonical signed Vega action") from None
    if type(result) is not dict:
        raise RuntimeError("native Vega action inspection returned an invalid result")
    return result


def inspect_signed_privacy_zk_ams_batch_admission_action_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
) -> dict[str, Any]:
    """Authenticate and inspect one exact ZK-AMS batch-admission action."""

    if not isinstance(
        signed_transaction_versioned,
        (bytes, bytearray, memoryview),
    ):
        raise TypeError("signed_transaction_versioned must be bytes-like")
    try:
        result = _crypto.inspect_signed_privacy_zk_ams_batch_admission_action_v1(
            bytes(signed_transaction_versioned)
        )
    except AttributeError as exc:
        raise RuntimeError(
            "iroha_native._crypto is missing "
            "inspect_signed_privacy_zk_ams_batch_admission_action_v1; "
            "rebuild the extension"
        ) from exc
    except Exception:
        raise ValueError("invalid canonical signed ZK-AMS batch-admission action") from None
    if type(result) is not dict:
        raise RuntimeError("native ZK-AMS batch-admission inspection returned an invalid result")
    return result


def inspect_signed_privacy_zk_ams_provision_account_action_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
) -> dict[str, Any]:
    """Authenticate and inspect one exact ZK-AMS account-provisioning action."""

    if not isinstance(
        signed_transaction_versioned,
        (bytes, bytearray, memoryview),
    ):
        raise TypeError("signed_transaction_versioned must be bytes-like")
    try:
        result = _crypto.inspect_signed_privacy_zk_ams_provision_account_action_v1(
            bytes(signed_transaction_versioned)
        )
    except AttributeError as exc:
        raise RuntimeError(
            "iroha_native._crypto is missing "
            "inspect_signed_privacy_zk_ams_provision_account_action_v1; "
            "rebuild the extension"
        ) from exc
    except Exception:
        raise ValueError("invalid canonical signed ZK-AMS account-provisioning action") from None
    if type(result) is not dict:
        raise RuntimeError(
            "native ZK-AMS account-provisioning inspection returned an invalid result"
        )
    return result


def inspect_signed_privacy_bootle_lantern_presentation_action_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
) -> dict[str, Any]:
    """Authenticate and inspect one exact Bootle/Lantern presentation action."""

    if not isinstance(
        signed_transaction_versioned,
        (bytes, bytearray, memoryview),
    ):
        raise TypeError("signed_transaction_versioned must be bytes-like")
    try:
        result = _crypto.inspect_signed_privacy_bootle_lantern_presentation_action_v1(
            bytes(signed_transaction_versioned)
        )
    except AttributeError as exc:
        raise RuntimeError(
            "iroha_native._crypto is missing "
            "inspect_signed_privacy_bootle_lantern_presentation_action_v1; "
            "rebuild the extension"
        ) from exc
    except Exception:
        raise ValueError("invalid canonical signed Bootle/Lantern presentation action") from None
    if type(result) is not dict:
        raise RuntimeError(
            "native Bootle/Lantern presentation inspection returned an invalid result"
        )
    return result


def _inspect_signed_privacy_native_action_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
    *,
    entrypoint: str,
    protocol_label: str,
) -> dict[str, Any]:
    if not isinstance(
        signed_transaction_versioned,
        (bytes, bytearray, memoryview),
    ):
        raise TypeError("signed_transaction_versioned must be bytes-like")
    try:
        inspector = getattr(_crypto, entrypoint)
    except AttributeError as exc:
        raise RuntimeError(
            f"iroha_native._crypto is missing {entrypoint}; rebuild the extension"
        ) from exc
    try:
        result = inspector(bytes(signed_transaction_versioned))
    except Exception:
        raise ValueError(f"invalid canonical signed {protocol_label} action") from None
    if type(result) is not dict:
        raise RuntimeError(f"native {protocol_label} action inspection returned an invalid result")
    return result


def inspect_signed_privacy_anonymous_pgc_payment_action_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
) -> dict[str, Any]:
    """Authenticate and inspect one exact Anonymous-PGC payment action."""

    return _inspect_signed_privacy_native_action_v1(
        signed_transaction_versioned,
        entrypoint="inspect_signed_privacy_anonymous_pgc_payment_action_v1",
        protocol_label="Anonymous-PGC",
    )


def inspect_signed_privacy_orchard_note_action_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
) -> dict[str, Any]:
    """Authenticate and inspect one exact Orchard note action."""

    return _inspect_signed_privacy_native_action_v1(
        signed_transaction_versioned,
        entrypoint="inspect_signed_privacy_orchard_note_action_v1",
        protocol_label="Orchard",
    )


def inspect_signed_privacy_fcmp_membership_payment_action_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
) -> dict[str, Any]:
    """Authenticate and inspect one exact FCMP++ membership payment."""

    return _inspect_signed_privacy_native_action_v1(
        signed_transaction_versioned,
        entrypoint="inspect_signed_privacy_fcmp_membership_payment_action_v1",
        protocol_label="FCMP++",
    )


def inspect_signed_privacy_ivm_private_note_action_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
) -> dict[str, Any]:
    """Authenticate and inspect one exact private-IVM note action."""

    return _inspect_signed_privacy_native_action_v1(
        signed_transaction_versioned,
        entrypoint="inspect_signed_privacy_ivm_private_note_action_v1",
        protocol_label="private-IVM",
    )


def inspect_signed_privacy_pq_masp_note_action_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
) -> dict[str, Any]:
    """Authenticate and inspect one exact PQ-MASP note action."""

    return _inspect_signed_privacy_native_action_v1(
        signed_transaction_versioned,
        entrypoint="inspect_signed_privacy_pq_masp_note_action_v1",
        protocol_label="PQ-MASP",
    )


def inspect_signed_privacy_zk_x509_identity_presentation_action_v1(
    signed_transaction_versioned: bytes | bytearray | memoryview,
    network_id: NetworkId,
) -> dict[str, Any]:
    """Authenticate and inspect one exact NetworkId-bound ZK-X509 presentation."""

    if not isinstance(
        signed_transaction_versioned,
        (bytes, bytearray, memoryview),
    ):
        raise TypeError("signed_transaction_versioned must be bytes-like")
    network_id = _require_network_id(network_id)
    entrypoint = "inspect_signed_privacy_zk_x509_identity_presentation_action_v1"
    try:
        inspector = getattr(_crypto, entrypoint)
    except AttributeError as exc:
        raise RuntimeError(
            f"iroha_native._crypto is missing {entrypoint}; rebuild the extension"
        ) from exc
    try:
        result = inspector(
            bytes(signed_transaction_versioned),
            network_id,
        )
    except Exception:
        raise ValueError("invalid canonical signed ZK-X509 presentation action") from None
    if type(result) is not dict:
        raise RuntimeError(
            "native ZK-X509 presentation action inspection returned an invalid result"
        )
    return result
