//! Closed canonical Advance shape validation for allocation-free fee eligibility.
//!
//! These static descriptors name only the existing Advance DTO fields. They authenticate
//! no source-chain claims; the originally admitted native verifier owns those checks.

use super::proof::SccpLcAdvanceV1;
use iroha_data_model::bridge::SccpNetworkV1;

enum Shape {
    Scalar(usize),
    ByteArray(usize),
    Bytes,
    Sequence(&'static Shape),
    Fields(&'static [Shape]),
    Option(&'static Shape),
    Enum(&'static [Option<Shape>]),
}
use Shape::{ByteArray, Bytes, Enum, Fields, Option as Optional, Scalar, Sequence};

const BYTE_VECTORS: Shape = Sequence(&Bytes);
const BEACON: Shape = Fields(&[
    Scalar(8),
    Scalar(8),
    ByteArray(32),
    ByteArray(32),
    ByteArray(32),
]);
const CAPELLA: Shape = Fields(&[
    ByteArray(32),
    Bytes,
    ByteArray(32),
    ByteArray(32),
    Bytes,
    ByteArray(32),
    Scalar(8),
    Scalar(8),
    Scalar(8),
    Scalar(8),
    Bytes,
    ByteArray(32),
    ByteArray(32),
    ByteArray(32),
    ByteArray(32),
]);
const EXECUTION: Shape = Enum(&[
    Some(CAPELLA),
    Some(Fields(&[CAPELLA, Scalar(8), Scalar(8)])),
]);
const HEADER: Shape = Fields(&[
    Enum(&[None, None, None, None, None, None]),
    BEACON,
    Optional(&EXECUTION),
    BYTE_VECTORS,
]);
const COMMITTEE: Shape = Fields(&[BYTE_VECTORS, Bytes]);
const NEXT_COMMITTEE: Shape = Fields(&[COMMITTEE, BYTE_VECTORS]);
const ETHEREUM: Shape = Fields(&[Sequence(&Fields(&[
    HEADER,
    Optional(&NEXT_COMMITTEE),
    HEADER,
    BYTE_VECTORS,
    Bytes,
    Bytes,
    Scalar(8),
]))]);
const BSC: Shape = Fields(&[Sequence(&Fields(&[
    BYTE_VECTORS,
    Fields(&[Scalar(8), Optional(&Scalar(8)), Bytes]),
]))]);
const TON_ID: Shape = Fields(&[
    Scalar(4),
    Scalar(8),
    Scalar(4),
    ByteArray(32),
    ByteArray(32),
]);
const SIGNATURES: Shape = Sequence(&Fields(&[ByteArray(32), Bytes]));
const TON_SIGNATURES: Shape = Enum(&[
    Some(Fields(&[Scalar(4), Scalar(4), SIGNATURES])),
    Some(Fields(&[
        Scalar(4),
        Scalar(4),
        ByteArray(32),
        Scalar(4),
        Bytes,
        SIGNATURES,
    ])),
]);
const TON: Shape = Fields(&[Sequence(&Fields(&[
    Fields(&[TON_ID, Bytes, TON_SIGNATURES]),
    Bytes,
]))]);

/// A cursor cannot allocate, recurse on wire-selected types, or read outside its source slice.
struct Cursor<'a> {
    rest: &'a [u8],
}
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let bytes = self.rest.get(..length)?;
        self.rest = self.rest.get(length..)?;
        Some(bytes)
    }
    fn count(&mut self) -> Option<usize> {
        usize::try_from(u64::from_le_bytes(self.take(8)?.try_into().ok()?)).ok()
    }
    fn field(&mut self) -> Option<&'a [u8]> {
        let mut length = 0_u64;
        for index in 0..10 {
            let byte = self.take(1)?[0];
            if index == 9 && byte > 1 {
                return None;
            }
            length |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                if index != 0 && byte == 0 {
                    return None;
                }
                return self.take(usize::try_from(length).ok()?);
            }
        }
        None
    }
    fn done(&self) -> Option<()> {
        self.rest.is_empty().then_some(())
    }
}

fn validate(shape: &Shape, bytes: &[u8]) -> Option<()> {
    let mut cursor = Cursor { rest: bytes };
    match shape {
        Scalar(width) => {
            cursor.take(*width)?;
        }
        ByteArray(count) => {
            for _ in 0..*count {
                if cursor.field()?.len() != 1 {
                    return None;
                }
            }
        }
        Bytes => {
            let count = cursor.count()?;
            cursor.take(count)?;
        }
        Sequence(element) => {
            let count = cursor.count()?;
            // Every element has at least one prefix byte, even when its payload is empty.
            if count > cursor.rest.len() {
                return None;
            }
            for _ in 0..count {
                validate(element, cursor.field()?)?;
            }
        }
        Fields(fields) => {
            for field in *fields {
                validate(field, cursor.field()?)?;
            }
        }
        Optional(value) => match cursor.take(1)?[0] {
            0 => {}
            1 => validate(value, cursor.field()?)?,
            _ => return None,
        },
        Enum(variants) => {
            let tag = usize::try_from(u32::from_le_bytes(cursor.take(4)?.try_into().ok()?)).ok()?;
            if let Some(value) = variants.get(tag)? {
                validate(value, cursor.field()?)?;
            }
        }
    }
    cursor.done()
}

pub(super) fn keeper_network(bytes: &[u8]) -> Option<SccpNetworkV1> {
    let payload = norito::canonical_frame_payload::<SccpLcAdvanceV1>(
        bytes,
        norito::core::default_encode_flags(),
    )
    .ok()?;
    let mut cursor = Cursor { rest: payload };
    let tag = u32::from_le_bytes(cursor.take(4)?.try_into().ok()?);
    let (shape, network) = match tag {
        0 => (&ETHEREUM, SccpNetworkV1::EthereumMainnet),
        1 => (&BSC, SccpNetworkV1::BscMainnet),
        2 => (&TON, SccpNetworkV1::TonMainnet),
        // Backfill can never be an exempt keeper advance, whether or not its body is valid.
        _ => return None,
    };
    validate(shape, cursor.field()?)?;
    cursor.done()?;
    Some(network)
}

#[cfg(test)]
mod tests;
