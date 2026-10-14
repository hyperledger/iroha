//! Complete original Name value census and closed directory-string policy.
//!
//! Public transition rows reject overlong UTF8, surrogates, values above
//! U+10FFFF and the profile's C0/C1 controls. Original byte and topology lookups
//! plus the OID-index copy bus bind each transition to an authenticated value.
use super::*;

pub(super) const ROWS: usize = 4 * 2 * 4 * 256;
pub(super) const PURPOSE: u16 = 14;
pub(super) const COPY_DOMAIN: u64 = 102;
pub(super) const RESIDUES: usize = 49;
const COUNTRY: usize = BASE_E;
const COUNTRY_INVERSE: usize = BASE_A;
const LAST_INVERSE: usize = BASE_D;
const INDEX: usize = BASE_G;
const LENGTH: usize = BASE_INSTANCE;
const BEFORE: usize = BASE_OFFSET;
const AFTER: usize = BASE_B;
const MODE: usize = BASE_ENDPOINT_ROLE;
const METADATA: [usize; 10] = [
    INDEX,
    BASE_H,
    BASE_DOCUMENT,
    BASE_NODE,
    BASE_CONTENT_START,
    BASE_DEPTH,
    BASE_TAG_NUMBER,
    BASE_TAG_CLASS,
    MODE,
    LENGTH,
];

/// Verifier-owned transition function: mode 0 country, 1 PrintableString,
/// 2 UTF8String; state zero alone accepts a complete sequence.
pub(super) fn transition(mode: u16, state: u16, byte: u8) -> Option<u16> {
    if mode == 0 {
        return (state == 0 && byte.is_ascii_uppercase()).then_some(0);
    }
    if mode == 1 {
        let printable = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b' ' | b'\'' | b'(' | b')' | b'+' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?'
            );
        return (state == 0 && printable).then_some(0);
    }
    if mode != 2 {
        return None;
    }
    match state {
        0 => match byte {
            0x20..=0x7e => Some(0),
            0xc2 => Some(8), // C2 80..9F are forbidden C1 controls.
            0xc3..=0xdf => Some(1),
            0xe0 => Some(4), // Exclude overlong three-byte sequences.
            0xe1..=0xec | 0xee..=0xef => Some(2),
            0xed => Some(5), // Exclude UTF16 surrogate code points.
            0xf0 => Some(6), // Exclude overlong four-byte sequences.
            0xf1..=0xf3 => Some(3),
            0xf4 => Some(7), // Cap at U+10FFFF.
            _ => None,
        },
        1..=3 if (0x80..=0xbf).contains(&byte) => Some(state - 1),
        4 if (0xa0..=0xbf).contains(&byte) => Some(1),
        5 if (0x80..=0x9f).contains(&byte) => Some(1),
        6 if (0x90..=0xbf).contains(&byte) => Some(2),
        7 if (0x80..=0x8f).contains(&byte) => Some(2),
        8 if (0xa0..=0xbf).contains(&byte) => Some(0),
        _ => None,
    }
}

pub(super) fn append_table(entries: &mut Vec<ZkX509Rfc5280ProfileByteEntryV1>) {
    for mode in 0..3 {
        for before in 0..9 {
            for byte in 0..=u8::MAX {
                if let Some(after) = transition(mode, before, byte) {
                    entries.push(ZkX509Rfc5280ProfileByteEntryV1 {
                        purpose: PURPOSE,
                        variant: mode,
                        source_role: ZkX509Rfc5280GrammarRoleV1::NameAttributeValue as u16,
                        offset: before,
                        length: after,
                        expected: byte,
                        contents_only: true,
                        exact_end: true,
                    });
                }
            }
        }
    }
}

pub(super) fn residues<A: PolynomialAirFieldV1>(
    row: &ZkX509Rfc5280StarkBaseRowV1<A>,
    next: &ZkX509Rfc5280StarkBaseRowV1<A>,
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
) -> [A; RESIDUES] {
    let family = fixed[ZkX509Rfc5280StarkFamilyV1::NameValue as usize];
    let gate = family.mul(row[BASE_ACTIVE]);
    let first = row[BASE_IS_WRITE];
    let last = row[BASE_STRICT];
    let country = row[COUNTRY];
    let mut result = [A::ZERO; RESIDUES];
    let mut count = 0;
    let mut push = |residue| {
        result[count] = residue;
        count += 1;
    };
    for (column, expected) in [
        (BASE_ROLE, PURPOSE as u64),
        (
            BASE_PARENT,
            ZkX509Rfc5280GrammarRoleV1::NameAttributeValue as u64,
        ),
        (BASE_ENDPOINT_INSTANCE, 1),
        (BASE_CHILD, 1),
    ] {
        push(gate.mul(row[column].sub(A::from_base(F(expected)))));
    }
    for flag in [first, last, country] {
        push(gate.mul(flag).mul(flag.sub(A::ONE)));
    }
    push(gate.mul(row[LENGTH].sub(row[BASE_TAG_NUMBER]).add(row[BASE_DEPTH])));
    let minus_one = (0..8).fold(A::ZERO, |sum, i| {
        sum.add(row[BASE_SMALL_BITS + i].mul_base(F(1 << i)))
    });
    push(gate.mul(row[LENGTH].sub(A::ONE).sub(minus_one)));
    for bit in &row[BASE_SMALL_BITS..BASE_SMALL_BITS + 8] {
        push(gate.mul(*bit).mul(bit.sub(A::ONE)));
    }
    let tag = row[BASE_TAG_CLASS];
    push(
        gate.mul(tag.sub(A::from_base(F(12))))
            .mul(tag.sub(A::from_base(F(19)))),
    );
    push(gate.mul(country).mul(row[INDEX]));
    push(
        gate.mul(
            row[INDEX]
                .mul(row[COUNTRY_INVERSE])
                .sub(A::ONE)
                .add(country),
        ),
    );
    push(gate.mul(country).mul(row[COUNTRY_INVERSE]));
    let inverse_seven = F(2_635_249_152_773_512_046);
    push(
        gate.mul(
            row[MODE]
                .sub(A::from_base(F(2)))
                .add(country)
                .add(tag.sub(A::from_base(F(12))).mul_base(inverse_seven)),
        ),
    );
    push(gate.mul(country).mul(row[LENGTH].sub(A::from_base(F(2)))));
    push(gate.mul(country).mul(tag.sub(A::from_base(F(19)))));
    let offset = row[BASE_ADDRESS].sub(row[BASE_DEPTH]);
    push(gate.mul(first).mul(offset));
    push(gate.mul(offset.mul(row[BASE_INVERSE]).sub(A::ONE).add(first)));
    push(gate.mul(first).mul(row[BASE_INVERSE]));
    let remaining = row[BASE_TAG_NUMBER].sub(row[BASE_ADDRESS]).sub(A::ONE);
    push(gate.mul(last).mul(remaining));
    push(gate.mul(remaining.mul(row[LAST_INVERSE]).sub(A::ONE).add(last)));
    push(gate.mul(last).mul(row[LAST_INVERSE]));
    push(gate.mul(first).mul(row[BEFORE]));
    push(gate.mul(last).mul(row[AFTER]));
    push(gate.mul(fixed[FIX_LOCAL_FIRST]).mul(first.sub(A::ONE)));
    push(gate.mul(fixed[FIX_LOCAL_LAST]).mul(last.sub(A::ONE)));
    push(
        gate.mul(A::ONE.sub(next[BASE_ACTIVE]))
            .mul(A::ONE.sub(last)),
    );
    push(
        family
            .mul(fixed[FIX_ACTIVATION_CONTINUE])
            .mul(next[BASE_ACTIVE])
            .mul(next[BASE_IS_WRITE].sub(last)),
    );
    let continuing = gate.mul(A::ONE.sub(last));
    push(continuing.mul(next[BASE_ACTIVE].sub(A::ONE)));
    push(continuing.mul(next[BASE_ADDRESS].sub(row[BASE_ADDRESS]).sub(A::ONE)));
    push(continuing.mul(next[BEFORE].sub(row[AFTER])));
    for column in METADATA {
        push(continuing.mul(next[column].sub(row[column])));
    }
    assert_eq!(count, RESIDUES);
    result
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn private_count(
    trace: &ZkX509Rfc5280TraceV1,
) -> Result<usize, ZkX509Rfc5280StarkErrorV1> {
    let count = role_nodes_v1(trace, ZkX509Rfc5280GrammarRoleV1::NameAttributeValue).try_fold(
        0_usize,
        |count, node| {
            let length = node
                .content_end
                .checked_sub(node.content_start)
                .filter(|length| (1..=256).contains(length))
                .ok_or(ZkX509Rfc5280StarkErrorV1::Semantic)?;
            count
                .checked_add(usize::from(length))
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)
        },
    )?;
    if count > ROWS {
        return Err(ZkX509Rfc5280StarkErrorV1::Resource);
    }
    Ok(count)
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn byte_multiplicity(
    trace: &ZkX509Rfc5280TraceV1,
    document: usize,
    address: usize,
) -> usize {
    role_nodes_v1(trace, ZkX509Rfc5280GrammarRoleV1::NameAttributeValue)
        .filter(|node| {
            usize::from(node.document) == document
                && usize::from(node.content_start) <= address
                && address < usize::from(node.content_end)
        })
        .count()
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
fn oid_index(
    trace: &ZkX509Rfc5280TraceV1,
    value: ZkX509Rfc5280NodeProvenanceV1,
) -> Result<usize, ZkX509Rfc5280StarkErrorV1> {
    let value_tlv_start = value.start;
    let mut nodes =
        role_nodes_v1(trace, ZkX509Rfc5280GrammarRoleV1::NameAttributeOid).filter(|node| {
            node.document == value.document
                && node.role_instance == value.role_instance
                && node.parent_node == value.parent_node
                && node.content_end == value_tlv_start
        });
    let oid = nodes.next().ok_or(ZkX509Rfc5280StarkErrorV1::Semantic)?;
    if nodes.next().is_some() {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    let source = source_slice_v1(trace, oid, true)?;
    NAME_OIDS_V1
        .into_iter()
        .position(|expected| {
            expected.len() == source.len()
                && expected
                    .iter()
                    .zip(source.iter())
                    .all(|(byte, cell)| *byte == cell.value)
        })
        .ok_or(ZkX509Rfc5280StarkErrorV1::Semantic)
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn populate_rows(
    trace: &ZkX509Rfc5280TraceV1,
    rows: &mut PrivateTableV1<ZkX509Rfc5280StarkBaseRowV1>,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    private_count(trace)?;
    for node in role_nodes_v1(trace, ZkX509Rfc5280GrammarRoleV1::NameAttributeValue) {
        let index = oid_index(trace, node)?;
        let length = node
            .content_end
            .checked_sub(node.content_start)
            .filter(|length| (1..=256).contains(length))
            .ok_or(ZkX509Rfc5280StarkErrorV1::Semantic)?;
        if node.tag_class != 0
            || node.constructed
            || !matches!(node.tag_number, 12 | 19)
            || (index == 0 && (node.tag_number != 19 || length != 2))
        {
            return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
        }
        let mode = if index == 0 {
            0
        } else if node.tag_number == 19 {
            1
        } else {
            2
        };
        let mut state = 0;
        for offset in 0..length {
            let address = node.content_start + offset;
            let byte = trace
                .documents
                .get(usize::from(node.document))
                .and_then(|document| document.bytes.get(usize::from(address)))
                .and_then(|cell| u8::try_from(cell.value.value.0).ok())
                .ok_or(ZkX509Rfc5280StarkErrorV1::Source)?;
            let after = transition(mode, state, byte).ok_or(ZkX509Rfc5280StarkErrorV1::Semantic)?;
            let remaining = length - offset - 1;
            let mut row = byte_row_v1(u64::from(node.document), u64::from(address), byte);
            row[COUNTRY_INVERSE] = F(index as u64).inverse_or_zero_canonical_v1();
            row[LAST_INVERSE] = F(u64::from(remaining)).inverse_or_zero_canonical_v1();
            row[COUNTRY] = F(u64::from(index == 0));
            row[INDEX] = F(index as u64);
            row[BASE_H] = F(u64::from(node.role_instance));
            row[LENGTH] = F(u64::from(length));
            row[BEFORE] = F(u64::from(state));
            row[AFTER] = F(u64::from(after));
            row[MODE] = F(u64::from(mode));
            row[BASE_NODE] = F(u64::from(node.node));
            row[BASE_PARENT] = F(ZkX509Rfc5280GrammarRoleV1::NameAttributeValue as u64);
            row[BASE_CHILD] = F::ONE;
            row[BASE_CONTENT_START] = F(u64::from(node.start));
            row[BASE_DEPTH] = F(u64::from(node.content_start));
            row[BASE_TAG_NUMBER] = F(u64::from(node.content_end));
            row[BASE_TAG_CLASS] = F(u64::from(node.tag_number));
            row[BASE_ROLE] = F(u64::from(PURPOSE));
            row[BASE_ENDPOINT_INSTANCE] = F::ONE;
            row[BASE_IS_WRITE] = F(u64::from(offset == 0));
            row[BASE_STRICT] = F(u64::from(remaining == 0));
            row[BASE_INVERSE] = F(u64::from(offset)).inverse_or_zero_canonical_v1();
            write_u8_bits_v1(&mut row, BASE_SMALL_BITS, (length - 1) as u8);
            push_family_row_v1(rows, row)?;
            state = after;
        }
        if state != 0 {
            return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn profile_multiplicity(
    rows: &PrivateTableV1<ZkX509Rfc5280StarkBaseRowV1>,
    entry: ZkX509Rfc5280ProfileByteEntryV1,
) -> usize {
    if entry.purpose != PURPOSE {
        return 0;
    }
    rows.iter()
        .filter(|row| {
            row[MODE] == F(u64::from(entry.variant))
                && row[BASE_PARENT] == F(u64::from(entry.source_role))
                && row[BEFORE] == F(u64::from(entry.offset))
                && row[AFTER] == F(u64::from(entry.length))
                && row[BASE_VALUE] == F(u64::from(entry.expected))
        })
        .count()
}
