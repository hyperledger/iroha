//! Benchmarks for Norito encoding and decoding of real chain wire payloads.
use criterion::Criterion;
use iroha_crypto::{Hash, HashOf, PrivateKey, PublicKey};
use iroha_data_model::{
    Level, NetworkId,
    account::{AccountController, AccountId, NewAccount},
    asset::{AssetDefinitionId, AssetId},
    block::{BlockHeader, SignedBlock, decode_framed_signed_block},
    isi::{InstructionBox, Log, Register, Transfer},
    transaction::signed::{SignedTransaction, TransactionBuilder, TransactionEntrypoint},
};
use iroha_model_base::domain::DomainId;
use iroha_primitives::const_vec::ConstVec;
use iroha_version::codec::{DecodeVersioned, EncodeVersioned};
use nonzero_ext::nonzero;
use norito::core::{self as ncore, DecodeFlagsGuard, header_flags};
use std::hint::black_box;
#[derive(Clone, Copy)]
struct LayoutCandidate {
    name: &'static str,
    flags: u8,
}
const LAYOUT_CANDIDATES: &[LayoutCandidate] = &[
    LayoutCandidate {
        name: "canonical",
        flags: 0,
    },
    LayoutCandidate {
        name: "compact_len",
        flags: header_flags::COMPACT_LEN,
    },
];
const MIXED_BLOCK_INSTRUCTION_COUNTS: &[usize] = &[0, 1, 4, 8, 16, 32];
fn fixed_public_key() -> PublicKey {
    "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
        .parse()
        .expect("fixed public key")
}
fn fixed_private_key() -> PrivateKey {
    "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
        .parse()
        .expect("fixed private key")
}
fn sample_asset_definition_id() -> AssetDefinitionId {
    let domain = DomainId::try_new("bench", "universal").expect("bench domain id");
    AssetDefinitionId::derive_from_components(domain, "xor".parse().expect("asset name"))
}
fn sample_instruction_box(kind: usize) -> InstructionBox {
    let authority = AccountId::new(fixed_public_key());
    let recipient = AccountId::new(fixed_public_key());
    match kind % 3 {
        0 => InstructionBox::from(Log::new(Level::INFO, format!("bench instruction {kind}"))),
        1 => InstructionBox::from(Transfer::asset_quantity(
            AssetId::new(sample_asset_definition_id(), authority),
            u64::try_from(1_000 + kind).expect("kind fits u64"),
            recipient,
        )),
        _ => InstructionBox::from(Register::account(NewAccount::new(recipient))),
    }
}
fn sample_transaction(instruction_count: usize) -> SignedTransaction {
    let private_key = fixed_private_key();
    let authority = AccountId::new(fixed_public_key());
    let network_id = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::new(b"norito-chain-wire-bench-genesis"),
    ));
    let instructions = (0..instruction_count)
        .map(sample_instruction_box)
        .collect::<Vec<_>>();
    TransactionBuilder::new(
        network_id,
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions)
    .sign(&private_key)
}
fn sample_genesis_transaction(instruction_count: usize) -> SignedTransaction {
    let private_key = fixed_private_key();
    let authority = AccountId::new(fixed_public_key());
    let instructions = (0..instruction_count)
        .map(sample_instruction_box)
        .collect::<Vec<_>>();
    TransactionBuilder::new_genesis(
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions)
    .sign(&private_key)
}
fn sample_block(transaction_count: usize, instruction_count: usize) -> SignedBlock {
    let private_key = fixed_private_key();
    let transactions = (0..transaction_count)
        .map(|_| sample_genesis_transaction(instruction_count))
        .collect::<Vec<_>>();
    SignedBlock::genesis(transactions, &private_key, None, None)
}
fn sample_mixed_block() -> SignedBlock {
    let private_key = fixed_private_key();
    let transactions = MIXED_BLOCK_INSTRUCTION_COUNTS
        .iter()
        .map(|&instruction_count| sample_genesis_transaction(instruction_count))
        .collect::<Vec<_>>();
    SignedBlock::genesis(transactions, &private_key, None, None)
}
fn report_size(label: &str, bytes: &[u8]) {
    eprintln!("{label} bytes={}", bytes.len());
}
fn report_layout_size(
    label: &str,
    candidate: LayoutCandidate,
    bytes: &[u8],
    framed: &[u8],
    actual_flags: u8,
) {
    eprintln!(
        "{label}/{} flags=0x{actual_flags:02x} bare_bytes={} framed_bytes={}",
        candidate.name,
        bytes.len(),
        framed.len()
    );
}
fn encode_with_layout<T>(value: &T, candidate: LayoutCandidate) -> (Vec<u8>, u8)
where
    T: norito::NoritoSerialize,
{
    let _guard = DecodeFlagsGuard::enter(candidate.flags);
    norito::codec::encode_with_header_flags(value)
}
fn decode_framed_with_layout<T>(bytes: &[u8]) -> T
where
    T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
{
    norito::decode_from_bytes::<T>(bytes).expect("decode framed benchmark payload")
}
fn bench_layout_candidates<T>(c: &mut Criterion, label: &str, value: &T)
where
    T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
{
    for &candidate in LAYOUT_CANDIDATES {
        let (bytes, actual_flags) = encode_with_layout(value, candidate);
        let framed = norito::core::frame_bare_with_header_flags::<T>(&bytes, actual_flags)
            .expect("frame benchmark payload");
        report_layout_size(label, candidate, &bytes, &framed, actual_flags);
        let encode_name = format!("chain_wire/layout/{label}/{}/encode", candidate.name);
        c.bench_function(&encode_name, |b| {
            b.iter(|| black_box(encode_with_layout(black_box(value), candidate)))
        });
        let decode_name = format!("chain_wire/layout/{label}/{}/decode_framed", candidate.name);
        let _: T = decode_framed_with_layout(&framed);
        c.bench_function(&decode_name, |b| {
            b.iter(|| black_box(decode_framed_with_layout::<T>(black_box(&framed))))
        });
    }
}
fn bench_instruction_codec(c: &mut Criterion) {
    for (label, instruction) in [
        ("log", sample_instruction_box(0)),
        ("transfer_asset", sample_instruction_box(1)),
        ("register_account", sample_instruction_box(2)),
    ] {
        let bare = norito::codec::encode_adaptive(&instruction);
        report_size(&format!("instruction_box/{label}/bare"), &bare);
        c.bench_function(&format!("chain_wire/instruction_box/{label}/encode"), |b| {
            b.iter(|| black_box(norito::codec::encode_adaptive(black_box(&instruction))))
        });
        c.bench_function(&format!("chain_wire/instruction_box/{label}/decode"), |b| {
            b.iter(|| {
                black_box(
                    norito::codec::decode_exact_from_slice::<InstructionBox>(black_box(&bare))
                        .expect("decode instruction box"),
                )
            })
        });
        bench_layout_candidates(c, &format!("instruction_box_{label}"), &instruction);
    }
}
fn bench_const_vec_instruction_box(c: &mut Criterion) {
    for &count in &[8usize, 32, 128] {
        let instructions = (0..count).map(sample_instruction_box).collect::<Vec<_>>();
        let value = ConstVec::from(instructions);
        let candidate = LayoutCandidate {
            name: "compact_len",
            flags: header_flags::COMPACT_LEN,
        };
        let (bare, actual_flags) = encode_with_layout(&value, candidate);
        let framed =
            ncore::frame_bare_with_header_flags::<ConstVec<InstructionBox>>(&bare, actual_flags)
                .expect("frame const vec instruction box");
        report_layout_size(
            &format!("const_vec_instruction_box_{count}"),
            candidate,
            &bare,
            &framed,
            actual_flags,
        );
        c.bench_function(
            &format!("chain_wire/const_vec_instruction_box/{count}/encode_compact_len"),
            |b| b.iter(|| black_box(encode_with_layout(black_box(&value), candidate))),
        );
        c.bench_function(
            &format!("chain_wire/const_vec_instruction_box/{count}/decode_compact_len"),
            |b| {
                b.iter(|| {
                    black_box(
                        norito::decode_from_bytes::<ConstVec<InstructionBox>>(black_box(&framed))
                            .expect("decode const vec instruction box"),
                    )
                })
            },
        );
    }
}
fn bench_public_key_and_account_decode(c: &mut Criterion) {
    let public_key = fixed_public_key();
    let public_key_bare = norito::codec::encode_adaptive(&public_key);
    let controller = AccountController::single(public_key.clone());
    let controller_framed = norito::to_bytes(&controller).expect("encode account controller");
    report_size("public_key/bare", &public_key_bare);
    report_size("account_controller_single/framed", &controller_framed);
    c.bench_function("chain_wire/public_key/decode", |b| {
        b.iter(|| {
            black_box(
                norito::codec::decode_exact_from_slice::<PublicKey>(black_box(&public_key_bare))
                    .expect("decode public key"),
            )
        })
    });
    c.bench_function(
        "chain_wire/account_controller/single_public_key/decode",
        |b| {
            b.iter(|| {
                black_box(
                    norito::decode_from_bytes::<AccountController>(black_box(&controller_framed))
                        .expect("decode account controller"),
                )
            })
        },
    );
}
fn bench_compact_lengths(c: &mut Criterion) {
    let values = [
        0_u64,
        1,
        63,
        127,
        128,
        255,
        16_383,
        16_384,
        1_048_576,
        u64::from(u32::MAX),
    ];
    let flags = header_flags::COMPACT_LEN;
    let encoded = values
        .iter()
        .map(|&value| {
            let mut bytes = Vec::new();
            ncore::write_len_to_vec_with_flags(&mut bytes, value, flags);
            bytes
        })
        .collect::<Vec<_>>();
    c.bench_function("chain_wire/compact_len/write_len_to_vec", |b| {
        b.iter(|| {
            let mut out = Vec::with_capacity(encoded.iter().map(Vec::len).sum());
            for &value in &values {
                ncore::write_len_to_vec_with_flags(&mut out, black_box(value), flags);
            }
            black_box(out);
        })
    });
    c.bench_function("chain_wire/compact_len/read_len_from_slice", |b| {
        b.iter(|| {
            for bytes in &encoded {
                black_box(
                    ncore::read_len_from_slice_with_flags(black_box(bytes), flags)
                        .expect("read compact length"),
                );
            }
        })
    });
}
fn bench_signed_transaction(c: &mut Criterion) {
    let tx = sample_transaction(8);
    let bare = norito::codec::encode_adaptive(&tx);
    let versioned = tx.encode_versioned();
    report_size("signed_transaction/bare", &bare);
    report_size("signed_transaction/versioned", &versioned);
    c.bench_function("chain_wire/signed_transaction/bare_encode", |b| {
        b.iter(|| black_box(norito::codec::encode_adaptive(black_box(&tx))))
    });
    c.bench_function("chain_wire/signed_transaction/bare_decode_exact", |b| {
        b.iter(|| {
            black_box(
                norito::codec::decode_exact_from_slice::<SignedTransaction>(black_box(&bare))
                    .expect("decode signed transaction"),
            )
        })
    });
    c.bench_function("chain_wire/signed_transaction/versioned_decode", |b| {
        b.iter(|| {
            black_box(
                SignedTransaction::decode_all_versioned(black_box(&versioned))
                    .expect("decode versioned signed transaction"),
            )
        })
    });
    bench_layout_candidates(c, "signed_transaction", &tx);
}
fn bench_signed_transaction_large(c: &mut Criterion) {
    let tx = sample_transaction(32);
    let bare = norito::codec::encode_adaptive(&tx);
    let versioned = tx.encode_versioned();
    report_size("signed_transaction_32/bare", &bare);
    report_size("signed_transaction_32/versioned", &versioned);
    c.bench_function("chain_wire/signed_transaction_32/bare_encode", |b| {
        b.iter(|| black_box(norito::codec::encode_adaptive(black_box(&tx))))
    });
    c.bench_function("chain_wire/signed_transaction_32/bare_decode_exact", |b| {
        b.iter(|| {
            black_box(
                norito::codec::decode_exact_from_slice::<SignedTransaction>(black_box(&bare))
                    .expect("decode signed transaction"),
            )
        })
    });
    c.bench_function("chain_wire/signed_transaction_32/versioned_decode", |b| {
        b.iter(|| {
            black_box(
                SignedTransaction::decode_all_versioned(black_box(&versioned))
                    .expect("decode versioned signed transaction"),
            )
        })
    });
    bench_layout_candidates(c, "signed_transaction_32", &tx);
}
fn bench_transaction_entrypoint(c: &mut Criterion) {
    let entrypoint = TransactionEntrypoint::from(sample_transaction(8));
    let bare = norito::codec::encode_adaptive(&entrypoint);
    let versioned = entrypoint.encode_versioned();
    report_size("transaction_entrypoint/bare", &bare);
    report_size("transaction_entrypoint/versioned", &versioned);
    c.bench_function("chain_wire/transaction_entrypoint/bare_encode", |b| {
        b.iter(|| black_box(norito::codec::encode_adaptive(black_box(&entrypoint))))
    });
    c.bench_function("chain_wire/transaction_entrypoint/bare_decode_exact", |b| {
        b.iter(|| {
            black_box(
                norito::codec::decode_exact_from_slice::<TransactionEntrypoint>(black_box(&bare))
                    .expect("decode transaction entrypoint"),
            )
        })
    });
    c.bench_function("chain_wire/transaction_entrypoint/versioned_decode", |b| {
        b.iter(|| {
            black_box(
                TransactionEntrypoint::decode_all_versioned(black_box(&versioned))
                    .expect("decode versioned transaction entrypoint"),
            )
        })
    });
    bench_layout_candidates(c, "transaction_entrypoint", &entrypoint);
}
fn bench_signed_block(c: &mut Criterion) {
    let block = sample_block(4, 4);
    let bare = norito::codec::encode_adaptive(&block);
    let versioned = block.encode_versioned();
    let wire = block.encode_wire().expect("encode signed block wire");
    report_size("signed_block/bare", &bare);
    report_size("signed_block/versioned", &versioned);
    report_size("signed_block/wire", &wire);
    c.bench_function("chain_wire/signed_block/bare_encode", |b| {
        b.iter(|| black_box(norito::codec::encode_adaptive(black_box(&block))))
    });
    c.bench_function("chain_wire/signed_block/bare_decode_exact", |b| {
        b.iter(|| {
            black_box(
                norito::codec::decode_exact_from_slice::<SignedBlock>(black_box(&bare))
                    .expect("decode signed block"),
            )
        })
    });
    c.bench_function("chain_wire/signed_block/wire_decode", |b| {
        b.iter(|| {
            black_box(
                decode_framed_signed_block(black_box(&wire)).expect("decode signed block wire"),
            )
        })
    });
    bench_layout_candidates(c, "signed_block", &block);
}
fn bench_signed_block_mixed(c: &mut Criterion) {
    let block = sample_mixed_block();
    let bare = norito::codec::encode_adaptive(&block);
    let versioned = block.encode_versioned();
    let wire = block.encode_wire().expect("encode signed block wire");
    report_size("signed_block_mixed/bare", &bare);
    report_size("signed_block_mixed/versioned", &versioned);
    report_size("signed_block_mixed/wire", &wire);
    c.bench_function("chain_wire/signed_block_mixed/bare_encode", |b| {
        b.iter(|| black_box(norito::codec::encode_adaptive(black_box(&block))))
    });
    c.bench_function("chain_wire/signed_block_mixed/bare_decode_exact", |b| {
        b.iter(|| {
            black_box(
                norito::codec::decode_exact_from_slice::<SignedBlock>(black_box(&bare))
                    .expect("decode signed block"),
            )
        })
    });
    c.bench_function("chain_wire/signed_block_mixed/wire_decode", |b| {
        b.iter(|| {
            black_box(
                decode_framed_signed_block(black_box(&wire)).expect("decode signed block wire"),
            )
        })
    });
    bench_layout_candidates(c, "signed_block_mixed", &block);
}
fn bench_empty_block_header(c: &mut Criterion) {
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let bare = norito::codec::encode_adaptive(&header);
    report_size("block_header/bare", &bare);
    c.bench_function("chain_wire/block_header/bare_encode", |b| {
        b.iter(|| black_box(norito::codec::encode_adaptive(black_box(&header))))
    });
    c.bench_function("chain_wire/block_header/bare_decode", |b| {
        b.iter(|| {
            black_box(
                norito::codec::decode_adaptive::<BlockHeader>(black_box(&bare))
                    .expect("decode block header"),
            )
        })
    });
}
fn main() {
    let mut c = Criterion::default().configure_from_args();
    bench_compact_lengths(&mut c);
    bench_public_key_and_account_decode(&mut c);
    bench_instruction_codec(&mut c);
    bench_const_vec_instruction_box(&mut c);
    bench_signed_transaction(&mut c);
    bench_signed_transaction_large(&mut c);
    bench_transaction_entrypoint(&mut c);
    bench_signed_block(&mut c);
    bench_signed_block_mixed(&mut c);
    bench_empty_block_header(&mut c);
    c.final_summary();
}
