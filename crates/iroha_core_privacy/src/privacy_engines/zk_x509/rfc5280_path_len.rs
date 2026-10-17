//! Complete private `BasicConstraints` bytes and nonwrapping u32 path-length slack.
//!
//! Each verifier-fixed certificate slot authenticates the complete contents of
//! its original signed extension OCTET STRING at ordinal three. The shared OID
//! identity constraints must bind that ordinal to `BasicConstraints`. Eight private canonical INTEGER variants
//! cover all u32 values; neither DER length nor path length becomes public.
use super::*;

pub(super) const ROWS_PER_SLOT: usize = 12;
pub(super) const SLOTS: usize = 3;
pub(super) const ROWS: usize = ROWS_PER_SLOT * SLOTS;
const VALUE_BITS: usize = GRAMMAR_CHILD_ORDINAL_BITS;
const SLACK_BITS: usize = CALENDAR_COLUMNS;
const VARIANTS: usize = BASE_SMALL_BITS;
pub(super) const PREFIX_END: usize = SLACK_BITS + 32;
const _: () = assert!(VALUE_BITS + 32 <= BASE_GRAMMAR_ORDINAL);
const _: () = assert!(PREFIX_END <= CALENDAR_END);

// These shared fixed cells have no other active interpretation on this family.
const SLOT: usize = FIX_EXPECTED;
const ADDRESS_OFFSET: usize = FIX_EXPECTED + 1;
const ADDRESS_LENGTH: usize = FIX_EXPECTED + 2;
const BYTE_CONSTANT: usize = FIX_EXPECTED + 3;
const BYTE_LENGTH: usize = FIX_EXPECTED + 4;
const BYTE_SELECTORS: usize = FIX_EXPECTED + 5;
const HEADER_QUERY: usize = FIX_EXPECTED + 9;
const CA: usize = FIX_ADDRESS_FIXED;
const OPTIONAL: usize = FIX_DOCUMENT_FIXED;
const METADATA: [usize; 16] = [
    BASE_A,
    BASE_B,
    BASE_E,
    BASE_F,
    BASE_G,
    BASE_INVERSE,
    BASE_DOCUMENT,
    BASE_NODE,
    BASE_START,
    BASE_CONTENT_START,
    BASE_CONTENT_END,
    BASE_ROLE,
    BASE_INSTANCE,
    BASE_TAG_CLASS,
    BASE_CONSTRUCTED,
    BASE_TAG_NUMBER,
];
// Includes all local equations and sixteen metadata/eight variant transitions.
pub(super) const RESIDUES: usize = 126;

pub(super) fn populate_fixed(fixed: &mut ZkX509Rfc5280StarkFixedRowV1, ordinal: usize) {
    if ordinal >= ROWS {
        return;
    }
    let slot = ordinal / ROWS_PER_SLOT;
    let offset = ordinal % ROWS_PER_SLOT;
    let ca = slot != 0;
    fixed[SLOT] = F(slot as u64);
    fixed[CA] = F(u64::from(ca));
    fixed[OPTIONAL] = F(u64::from(slot == 2));
    fixed[FIX_REQUIRED_ACTIVE] = F(u64::from(slot < 2));
    fixed[FIX_LOCAL_FIRST] = F(u64::from(offset == 0));
    fixed[FIX_LOCAL_LAST] = F(u64::from(offset + 1 == ROWS_PER_SLOT));
    if offset < 7 {
        fixed[ADDRESS_OFFSET] = F(offset as u64);
        fixed[HEADER_QUERY] = F(u64::from(ca || offset < 2));
        fixed[BYTE_CONSTANT] = F(if ca {
            [0x30, 5, 1, 1, 0xff, 2, 0][offset]
        } else {
            u64::from(offset == 0) * 0x30
        });
        fixed[BYTE_LENGTH] = F(u64::from(ca && matches!(offset, 1 | 6)));
    } else if ca {
        fixed[ADDRESS_OFFSET] = F((offset - 5) as u64);
        fixed[ADDRESS_LENGTH] = F::ONE;
        if offset >= 8 {
            fixed[BYTE_SELECTORS + offset - 8] = F::ONE;
        }
    }
}

pub(super) fn byte_query_gate<A: PolynomialAirFieldV1>(
    row: &ZkX509Rfc5280StarkBaseRowV1<A>,
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
) -> A {
    fixed[ZkX509Rfc5280StarkFamilyV1::BasicConstraints as usize].mul(row[BASE_D])
}

pub(super) fn node_query_gate<A: PolynomialAirFieldV1>(
    row: &ZkX509Rfc5280StarkBaseRowV1<A>,
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
) -> A {
    fixed[ZkX509Rfc5280StarkFamilyV1::BasicConstraints as usize].mul(row[BASE_IS_WRITE])
}

pub(super) fn append_residues<A: PolynomialAirFieldV1>(
    row: &ZkX509Rfc5280StarkBaseRowV1<A>,
    next: &ZkX509Rfc5280StarkBaseRowV1<A>,
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
    output: &mut Vec<A>,
) {
    let before = output.len();
    let gate = fixed[ZkX509Rfc5280StarkFamilyV1::BasicConstraints as usize];
    let active = row[BASE_ACTIVE];
    let variants = &row[VARIANTS..VARIANTS + 8];
    let selected = variants.iter().copied().fold(A::ZERO, A::add);
    let bytes: [A; 4] = core::array::from_fn(|index| {
        pack_bits_v1(&row[VALUE_BITS + index * 8..VALUE_BITS + index * 8 + 8])
    });
    let mut leading = A::ZERO;
    let mut leading_sign = A::ZERO;
    let mut sign = A::ZERO;
    let mut length = A::ZERO;
    let mut nonzero = A::ZERO;
    let mut total = active.mul_base(F(2));
    let mut live = [A::ZERO; 5];
    for (index, variant) in variants.iter().copied().enumerate() {
        let magnitude = index / 2 + 1;
        let padding = index % 2;
        let count = magnitude + padding;
        leading = leading.add(variant.mul(bytes[magnitude - 1]));
        leading_sign = leading_sign.add(variant.mul(row[VALUE_BITS + magnitude * 8 - 1]));
        if padding == 1 {
            sign = sign.add(variant);
        }
        if magnitude > 1 {
            nonzero = nonzero.add(variant);
        }
        length = length.add(variant.mul_base(F(count as u64)));
        total = total.add(variant.mul_base(F((5 + count) as u64)));
        for (position, live) in live.iter_mut().enumerate() {
            if count > position {
                *live = live.add(variant);
            }
        }
    }
    let mut push = |residue: A| output.push(gate.mul(residue));
    push(
        active
            .sub(fixed[FIX_REQUIRED_ACTIVE])
            .sub(fixed[OPTIONAL].mul(row[BASE_CERT2_ACTIVE])),
    );
    for value in variants
        .iter()
        .chain(&row[VALUE_BITS..VALUE_BITS + 32])
        .chain(&row[SLACK_BITS..SLACK_BITS + 32])
    {
        push(value.mul(value.sub(A::ONE)));
    }
    push(selected.sub(fixed[CA].mul(active)));
    push(row[BASE_E].sub(pack_bits_v1(&row[VALUE_BITS..VALUE_BITS + 32])));
    push(row[BASE_F].sub(pack_bits_v1(&row[SLACK_BITS..SLACK_BITS + 32])));
    push(A::ONE.sub(selected).mul(row[BASE_E]));
    push(A::ONE.sub(selected).mul(row[BASE_F]));
    // Both operands are <=u32::MAX; the difference cannot wrap in Goldilocks.
    push(
        row[BASE_E]
            .sub(row[BASE_F])
            .sub(fixed[SLOT].sub(fixed[CA]).mul(active)),
    );
    for (index, byte) in bytes.iter().copied().enumerate().skip(1) {
        let omitted = variants[..index * 2].iter().copied().fold(A::ZERO, A::add);
        push(omitted.mul(byte));
    }
    push(row[BASE_G].sub(leading));
    push(sign.sub(leading_sign));
    push(nonzero.mul(row[BASE_G].mul(row[BASE_INVERSE]).sub(A::ONE)));
    push(A::ONE.sub(nonzero).mul(row[BASE_INVERSE]));
    push(row[BASE_B].sub(length));
    let selectors = &fixed[BYTE_SELECTORS..BYTE_SELECTORS + 4];
    let first_integer = fixed[CA]
        .sub(fixed[HEADER_QUERY])
        .sub(selectors.iter().copied().fold(A::ZERO, A::add));
    let mut query = fixed[HEADER_QUERY]
        .mul(active)
        .add(first_integer.mul(live[4]));
    let mut expected = fixed[BYTE_CONSTANT]
        .mul(active)
        .add(fixed[BYTE_LENGTH].mul(length));
    for (index, selector) in selectors.iter().copied().enumerate() {
        query = query.add(selector.mul(live[3 - index]));
        expected = expected.add(selector.mul(bytes[3 - index]));
    }
    push(row[BASE_D].mul(row[BASE_D].sub(A::ONE)));
    push(row[BASE_D].sub(query));
    push(row[BASE_VALUE].sub(expected));
    push(
        row[BASE_D].mul(
            row[BASE_ADDRESS]
                .sub(row[BASE_CONTENT_START])
                .sub(fixed[ADDRESS_OFFSET])
                .sub(fixed[ADDRESS_LENGTH].mul(length)),
        ),
    );
    push(A::ONE.sub(row[BASE_D]).mul(row[BASE_ADDRESS]));
    push(A::ONE.sub(row[BASE_D]).mul(row[BASE_VALUE]));
    push(row[BASE_IS_WRITE].sub(fixed[FIX_LOCAL_FIRST].mul(active)));
    for difference in [
        row[BASE_DOCUMENT].sub(fixed[SLOT].mul(active)),
        row[BASE_ROLE].sub(active.mul_base(F(
            ZkX509Rfc5280GrammarRoleV1::CertificateExtensionValue as u64,
        ))),
        row[BASE_INSTANCE].sub(active.mul_base(F(3))),
        row[BASE_TAG_CLASS],
        row[BASE_CONSTRUCTED],
        row[BASE_TAG_NUMBER].sub(active.mul_base(F(4))),
        row[BASE_A].sub(total),
        row[BASE_CONTENT_END]
            .sub(row[BASE_CONTENT_START])
            .sub(row[BASE_A]),
    ] {
        push(difference);
    }
    for column in METADATA.into_iter().chain(VARIANTS..VARIANTS + 8) {
        push(
            A::ONE
                .sub(fixed[FIX_LOCAL_LAST])
                .mul(next[column].sub(row[column])),
        );
    }
    assert_eq!(output.len() - before, RESIDUES);
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy)]
pub(super) struct Source<'a> {
    node: &'a ZkX509Rfc5280NodeProvenanceV1,
    value: Option<&'a u32>,
}

// The largest canonical BasicConstraints encoding is twelve bytes. Keep this
// comparison scratch on the stack and clear both private bytes and length on
// every return, including source-validation failures.
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct CanonicalFrame {
    bytes: [u8; ROWS_PER_SLOT],
    length: u8,
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
impl CanonicalFrame {
    fn new(value: Option<u32>) -> Self {
        let mut frame = Self {
            bytes: [0; ROWS_PER_SLOT],
            length: 2,
        };
        frame.bytes[0] = 0x30;
        if let Some(value) = value {
            let magnitude = ((32 - value.leading_zeros()).max(1) as usize).div_ceil(8);
            let padding = usize::from(value & (1 << (magnitude * 8 - 1)) != 0);
            let integer_length = magnitude + padding;
            frame.length = (7 + integer_length) as u8;
            frame.bytes[1] = 5 + integer_length as u8;
            frame.bytes[2] = 1;
            frame.bytes[3] = 1;
            frame.bytes[4] = 0xff;
            frame.bytes[5] = 2;
            frame.bytes[6] = integer_length as u8;
            for index in 0..magnitude {
                frame.bytes[7 + padding + index] = (value >> (8 * (magnitude - index - 1))) as u8;
            }
        }
        frame
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for CanonicalFrame {
    fn drop(&mut self) {
        zeroize_words_v1(&mut self.bytes);
        zeroize_words_v1(core::slice::from_mut(&mut self.length));
    }
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn sources(
    trace: &ZkX509Rfc5280TraceV1,
) -> Result<[Option<Source<'_>>; SLOTS], ZkX509Rfc5280StarkErrorV1> {
    if !(2..=SLOTS).contains(&trace.certificates.len()) {
        return Err(ZkX509Rfc5280StarkErrorV1::Shape);
    }
    let mut result = [None; SLOTS];
    for (slot, certificate) in trace.certificates.iter().enumerate() {
        let mut nodes = trace
            .semantic_provenance
            .get(slot)
            .ok_or(ZkX509Rfc5280StarkErrorV1::Source)?
            .nodes
            .iter()
            .filter(|node| {
                node.role == ZkX509Rfc5280GrammarRoleV1::CertificateExtensionValue
                    && node.role_instance == 3
            });
        let node = nodes.next().ok_or(ZkX509Rfc5280StarkErrorV1::Source)?;
        let value = certificate.extensions.basic_constraints_path_len.as_ref();
        if nodes.next().is_some()
            || usize::from(node.document) != slot
            || node.tag_class != 0
            || node.constructed
            || node.tag_number != 4
            || certificate.extensions.basic_constraints_ca != (slot != 0)
            || value.is_some() != (slot != 0)
            || value.is_some_and(|value| *value < slot.saturating_sub(1) as u32)
        {
            return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
        }
        let frame = CanonicalFrame::new(value.copied());
        let expected = frame.as_slice();
        let contents = trace
            .documents
            .get(slot)
            .and_then(|document| {
                document
                    .bytes
                    .get(usize::from(node.content_start)..usize::from(node.content_end))
            })
            .ok_or(ZkX509Rfc5280StarkErrorV1::Source)?;
        if contents.len() != expected.len()
            || contents
                .iter()
                .zip(expected.iter())
                .any(|(actual, expected)| actual.value.value != F(u64::from(*expected)))
        {
            return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
        }
        result[slot] = Some(Source { node, value });
    }
    Ok(result)
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn byte_multiplicity(
    sources: &[Option<Source<'_>>; SLOTS],
    document: usize,
    address: usize,
) -> usize {
    sources
        .iter()
        .flatten()
        .filter(|source| {
            usize::from(source.node.document) == document
                && (usize::from(source.node.content_start)..usize::from(source.node.content_end))
                    .contains(&address)
        })
        .count()
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn node_multiplicity(
    sources: &[Option<Source<'_>>; SLOTS],
    document: usize,
    node: usize,
) -> u16 {
    sources
        .iter()
        .flatten()
        .filter(|source| {
            usize::from(source.node.document) == document && usize::from(source.node.node) == node
        })
        .count() as u16
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn append_rows(
    trace: &ZkX509Rfc5280TraceV1,
    sources: &[Option<Source<'_>>; SLOTS],
    rows: &mut Vec<ZkX509Rfc5280StarkBaseRowV1>,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    for (slot, source) in sources.iter().enumerate() {
        let Some(source) = source else {
            continue;
        };
        let value = source.value.copied().unwrap_or(0);
        let slack = value
            .checked_sub(slot.saturating_sub(1) as u32)
            .ok_or(ZkX509Rfc5280StarkErrorV1::Semantic)?;
        let magnitude = ((32 - value.leading_zeros()).max(1) as usize).div_ceil(8);
        let padding = usize::from(value & (1 << (magnitude * 8 - 1)) != 0);
        let length = if slot == 0 { 0 } else { magnitude + padding };
        for offset in 0..ROWS_PER_SLOT {
            let mut row = active_zero_row_v1();
            let node = source.node;
            row[BASE_A] = F(u64::from(node.content_end - node.content_start));
            row[BASE_B] = F(length as u64);
            row[BASE_E] = F(u64::from(value));
            row[BASE_F] = F(u64::from(slack));
            row[BASE_DOCUMENT] = F(u64::from(node.document));
            row[BASE_NODE] = F(u64::from(node.node));
            row[BASE_START] = F(u64::from(node.start));
            row[BASE_CONTENT_START] = F(u64::from(node.content_start));
            row[BASE_CONTENT_END] = F(u64::from(node.content_end));
            row[BASE_ROLE] = F(node.role as u64);
            row[BASE_INSTANCE] = F(u64::from(node.role_instance));
            row[BASE_TAG_CLASS] = F(u64::from(node.tag_class));
            row[BASE_CONSTRUCTED] = F(u64::from(node.constructed));
            row[BASE_TAG_NUMBER] = F(u64::from(node.tag_number));
            row[BASE_IS_WRITE] = F(u64::from(offset == 0));
            for bit in 0..32 {
                row[VALUE_BITS + bit] = F(u64::from((value >> bit) & 1));
                row[SLACK_BITS + bit] = F(u64::from((slack >> bit) & 1));
            }
            if slot != 0 {
                row[VARIANTS + (magnitude - 1) * 2 + padding] = F::ONE;
                row[BASE_G] = F(u64::from(value >> ((magnitude - 1) * 8)));
                if magnitude > 1 {
                    // Canonical magnitude selection proves this leading u8 is nonzero.
                    row[BASE_INVERSE] = row[BASE_G].inverse_or_zero_canonical_v1();
                }
            }
            let live = if slot == 0 {
                offset < 2
            } else {
                offset < 7 || offset - 7 >= 5 - length
            };
            row[BASE_D] = F(u64::from(live));
            if live {
                let relative = if offset < 7 {
                    offset
                } else {
                    offset - 5 + length
                };
                let address = usize::from(node.content_start)
                    .checked_add(relative)
                    .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
                let byte = trace
                    .documents
                    .get(slot)
                    .and_then(|document| document.bytes.get(address))
                    .ok_or(ZkX509Rfc5280StarkErrorV1::Source)?
                    .value
                    .value;
                let byte = u8::try_from(byte.0).map_err(|_| ZkX509Rfc5280StarkErrorV1::Source)?;
                row[BASE_ADDRESS] = F(address as u64);
                row[BASE_VALUE] = F(u64::from(byte));
                write_u8_bits_v1(&mut row, BASE_BYTE_BITS, byte);
            }
            push_family_row_v1(rows, row)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "rfc5280_path_len_tests.rs"]
mod tests;
