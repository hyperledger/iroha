//! Bounded, untrusted TON destination discovery for the node keeper.
//!
//! These readers confer no TON finality or SCCP authority. Every discovered certificate
//! must pass the Core original-state forgery verifier before it can be submitted.

use super::*;

/// Exact transaction position used only to continue an untrusted account history scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    /// Account transaction logical time.
    pub lt: u64,
    /// Transaction root representation hash.
    pub hash: H256,
}

/// Fixed bytes of a published `SccpCertificateEvent`, still unverified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// Original fixed QC encoding, including the signer word.
    pub qc: [u8; 116],
    /// Original X encoding.
    pub header: [u8; 221],
    /// Compressed G2 aggregate signature.
    pub aggregate_signature: [u8; 96],
}

/// Untrusted destination progress observation; never a consensus or funding fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// A reported successor and its expiry.
    Rotation {
        /// Installed generation.
        generation: u64,
        /// Reported absolute expiry.
        until_ms: u64,
    },
    /// A reported stored checkpoint.
    Checkpoint {
        /// Checkpoint height.
        height: u64,
    },
    /// A reported permanent latch.
    Latch {
        /// Generation in the latch event.
        generation: u64,
        /// Height in the latch event.
        height: u64,
    },
}

/// Untrusted final destination effect, linked to an exact successful account transaction.
/// Wallets must authenticate its source-chain proof before treating it as final settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalEvent {
    /// A wallet mint completed and the minter published its exact message identity.
    Finalized {
        /// Original message identity.
        message_id: H256,
        /// Original outbound nonce.
        nonce: u64,
    },
    /// The destination permanently consumed a nonce without minting.
    Voided {
        /// Bound single-message identity, or the protocol's range sentinel.
        message_id: H256,
        /// First nonce in the void range.
        first_nonce: u64,
        /// Number of permanently consumed nonces.
        count: u16,
    },
}

/// A terminal event's exact source position for the shared proof builder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalObservation {
    /// Exact minter account transaction.
    pub transaction: Cursor,
    /// External-out message index in that transaction.
    pub message_index: u16,
    /// Decoded effect, still subject to source-chain finality verification.
    pub event: TerminalEvent,
}

/// A successful burn bound to the exact incoming notification query id and sender wallet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BurnObservation {
    /// Exact finalized-proof transaction position.
    pub transaction: Cursor,
    /// Outgoing transfer event index.
    pub message_index: u16,
    /// Unique retained request id propagated through the wallet burn notification.
    pub query_id: u64,
    /// Canonical Jetton wallet that sent the notification.
    pub notification_sender: H256,
    /// Computed SCCP message identity.
    pub message_id: H256,
    /// Assigned minter outbound nonce.
    pub nonce: u64,
    /// Burning basechain owner.
    pub owner: H256,
    /// Exact positive token amount.
    pub amount: u128,
    /// Hash of the canonical emitted transfer payload.
    pub payload_hash: H256,
}

fn skip_balance(reader: &mut TonBitReader<'_>) -> Option<()> {
    reader.skip_bits(5)?;
    ton_skip_currency_collection(reader)
}

/// Read a discovery cursor from a liteserver's original account-state proof.
/// The proof's shard-state account key must equal the requested basechain account.
#[must_use]
pub fn account_cursor(proof: &[u8], account: &H256) -> Option<Cursor> {
    let boc = parse_ton_boc(proof)?;
    if boc.roots.is_empty() || boc.roots.len() > 2 {
        return None;
    }
    let mut found = None;
    for root in &boc.roots {
        let index = ton_virtual_root_index(&boc, *root)?;
        let mut reader = TonBitReader::new(boc.cells.get(index)?)?;
        if reader.read_u64(32)? != u64::from(TON_SHARD_STATE_CONSTRUCTOR) {
            continue;
        }
        if reader.read_i32(32)? != TON_MAINNET_GLOBAL_ID {
            return None;
        }
        let (workchain, _) = ton_read_shard_ident(&mut reader)?;
        if workchain != TON_BASECHAIN_WORKCHAIN {
            return None;
        }
        reader.skip_bits(32 + 32 + 32 + 64 + 32)?;
        reader.read_ref()?;
        reader.read_bit()?;
        let accounts = reader.read_ref()?;
        let root = ton_hashmap_aug_e_root(&boc, accounts, skip_balance)?;
        let mut leaf = ton_hashmap_aug_leaf_reader(&boc, root, account, 256, skip_balance)?;
        skip_balance(&mut leaf)?;
        leaf.read_ref()?;
        let cursor = Cursor {
            hash: leaf.read_h256()?,
            lt: leaf.read_u64(64)?,
        };
        if !leaf.exhausted() || cursor.lt == 0 || found.is_some() {
            return None;
        }
        found = Some(cursor);
    }
    found
}

/// Refusal to accept an untrusted destination transaction page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificatePageError {
    /// The page is malformed, unlinked or exceeds the fixed root limit.
    InvalidPage,
    /// The visitor refused a discovered certificate.
    VisitorRefused,
}

impl core::fmt::Display for CertificatePageError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPage => "invalid destination transaction page",
            Self::VisitorRefused => "destination certificate visitor refused",
        })
    }
}

impl std::error::Error for CertificatePageError {}

/// Visit certificates in at most sixteen linked account transaction roots.
///
/// Returns the next older cursor, or `None` once the account history ends. The callback
/// may refuse immediately; false or malformed data fails the complete page. No list of
/// certificates is copied. Ordinary unrelated transactions advance the discovery cursor.
///
/// # Errors
/// Returns [`CertificatePageError`] for invalid pages or callback refusal.
pub fn certificates(
    bytes: &[u8],
    account: &H256,
    cursor: Cursor,
    visit: impl FnMut(Certificate) -> bool,
    observe: impl FnMut(Progress),
) -> Result<Option<Cursor>, CertificatePageError> {
    visit_page(bytes, account, cursor, visit, observe, |_| true, |_| true)
}

/// Discover final mint/void effects in one bounded, hash-linked transaction page.
/// No missing event proves failure; the resulting source position requires a finalized proof.
///
/// # Errors
/// Refuses malformed pages, unsuccessful event transactions and visitor refusal.
pub fn terminal_events(
    bytes: &[u8],
    account: &H256,
    cursor: Cursor,
    visit: impl FnMut(TerminalObservation) -> bool,
) -> Result<Option<Cursor>, CertificatePageError> {
    visit_page(bytes, account, cursor, |_| true, |_| {}, visit, |_| true)
}

/// Discover successful burns causally bound to their original wallet notification.
/// Every result still requires the shared finalized source proof.
///
/// # Errors
/// Refuses malformed pages and callback refusals.
pub fn burns(
    bytes: &[u8],
    account: &H256,
    cursor: Cursor,
    visit: impl FnMut(BurnObservation) -> bool,
) -> Result<Option<Cursor>, CertificatePageError> {
    visit_page(bytes, account, cursor, |_| true, |_| {}, |_| true, visit)
}

fn burn_notification(
    boc: &TonBoc,
    transaction: TonParsedTransaction,
    account: &H256,
) -> Option<(u64, H256)> {
    let mut auxiliary = ordinary(boc, transaction.auxiliary_index)?;
    auxiliary.read_bit()?.then_some(())?;
    let mut message = ordinary(boc, auxiliary.read_ref()?)?;
    (!message.read_bit()?).then_some(())?; // internal message
    message.read_bit()?; // IHR disabled
    message.read_bit()?; // bounce
    (!message.read_bit()?).then_some(())?; // not a bounce
    let source = ton_read_canonical_std_address(&mut message)?.account;
    (ton_read_canonical_std_address(&mut message)?.account == *account).then_some(())?;
    ton_skip_currency_collection(&mut message)?;
    ton_skip_grams(&mut message)?;
    ton_skip_grams(&mut message)?;
    message.skip_bits(64 + 32)?;
    (!message.read_bit()?).then_some(())?; // no StateInit
    let mut body = if message.read_bit()? {
        let body = ordinary(boc, message.read_ref()?)?;
        message.exhausted().then_some(())?;
        body
    } else {
        message
    };
    (body.read_u64(32)? == 0x7bdd_97de).then_some(())?;
    Some((body.read_u64(64)?, source))
}

fn visit_page(
    bytes: &[u8],
    account: &H256,
    cursor: Cursor,
    mut visit: impl FnMut(Certificate) -> bool,
    mut observe: impl FnMut(Progress),
    mut terminal: impl FnMut(TerminalObservation) -> bool,
    mut burn: impl FnMut(BurnObservation) -> bool,
) -> Result<Option<Cursor>, CertificatePageError> {
    let boc = parse_ton_boc(bytes).ok_or(CertificatePageError::InvalidPage)?;
    if boc.roots.is_empty() || boc.roots.len() > 16 {
        return Err(CertificatePageError::InvalidPage);
    }
    let hashes = ton_boc_cell_hashes(&boc).ok_or(CertificatePageError::InvalidPage)?;
    let mut expected = cursor;
    for root in &boc.roots {
        let cell = boc
            .cells
            .get(*root)
            .ok_or(CertificatePageError::InvalidPage)?;
        if ton_cell_type(cell) != Some(TonCellType::Ordinary)
            || hashes
                .get(*root)
                .ok_or(CertificatePageError::InvalidPage)?
                .hashes[0]
                != expected.hash
        {
            return Err(CertificatePageError::InvalidPage);
        }
        let mut reader = TonBitReader::new(cell).ok_or(CertificatePageError::InvalidPage)?;
        if reader.read_u64(4) != Some(7)
            || reader.read_h256() != Some(*account)
            || reader.read_u64(64) != Some(expected.lt)
        {
            return Err(CertificatePageError::InvalidPage);
        }
        let previous = Cursor {
            hash: reader
                .read_h256()
                .ok_or(CertificatePageError::InvalidPage)?,
            lt: reader
                .read_u64(64)
                .ok_or(CertificatePageError::InvalidPage)?,
        };
        if previous.lt >= expected.lt {
            return Err(CertificatePageError::InvalidPage);
        }
        if let Some(transaction) = ton_parse_transaction(&boc, *root, *account, expected.lt) {
            for index in 0..transaction.out_message_count {
                let message = ton_transaction_out_message(&boc, transaction, index)
                    .ok_or(CertificatePageError::InvalidPage)?;
                if let Some(body) = ton_sccp_ext_out_body(&boc, message, account) {
                    let mut probe = body.clone();
                    if probe.read_u64(32) == Some(0x5343_4346) {
                        let cert = certificate_body(&boc, body)
                            .ok_or(CertificatePageError::InvalidPage)?;
                        if !visit(cert) {
                            return Err(CertificatePageError::VisitorRefused);
                        }
                    } else if let Some(event) = terminal_body(body.clone()) {
                        if ton_transaction_succeeded(&boc, transaction) != Some(true) {
                            return Err(CertificatePageError::InvalidPage);
                        }
                        if !terminal(TerminalObservation {
                            transaction: expected,
                            message_index: index,
                            event,
                        }) {
                            return Err(CertificatePageError::VisitorRefused);
                        }
                    } else if let Some(TonSccpEventV1::TransferToTaira {
                        message_id,
                        nonce,
                        sender,
                        amount,
                        payload,
                    }) =
                        ton_parse_sccp_event_body_with(&boc, body.clone(), &Memory::detached())
                    {
                        if let Some((query_id, notification_sender)) =
                            burn_notification(&boc, transaction, account)
                        {
                            if ton_transaction_succeeded(&boc, transaction) != Some(true) {
                                return Err(CertificatePageError::InvalidPage);
                            }
                            if !burn(BurnObservation {
                                transaction: expected,
                                message_index: index,
                                query_id,
                                notification_sender,
                                message_id,
                                nonce,
                                owner: sender,
                                amount,
                                payload_hash: crate::v1::hashes::payload_hash(&payload),
                            }) {
                                return Err(CertificatePageError::VisitorRefused);
                            }
                        }
                    } else if let Some(progress) = progress_body(body) {
                        observe(progress);
                    }
                }
            }
        }
        expected = previous;
    }
    Ok((expected.lt != 0).then_some(expected))
}

fn terminal_body(mut body: TonBitReader<'_>) -> Option<TerminalEvent> {
    let event = match body.read_u64(32)? {
        value if value == u64::from(TON_SCCP_FINALIZED_OP) => TerminalEvent::Finalized {
            message_id: body.read_h256()?,
            nonce: body.read_u64(64)?,
        },
        value if value == u64::from(TON_SCCP_VOIDED_OP) => TerminalEvent::Voided {
            message_id: body.read_h256()?,
            first_nonce: body.read_u64(64)?,
            count: u16::try_from(body.read_u64(16)?).ok()?,
        },
        _ => return None,
    };
    body.exhausted().then_some(event)
}

fn progress_body(mut body: TonBitReader<'_>) -> Option<Progress> {
    let event = match body.read_u64(32)? {
        0x5343_5252 => {
            let generation = body.read_u64(64)?;
            body.read_h256()?;
            let until_ms = body.read_u64(64)?;
            body.read_u64(64)?;
            Progress::Rotation {
                generation,
                until_ms,
            }
        }
        0x5343_4b4e => {
            let height = body.read_u64(64)?;
            body.read_h256()?;
            Progress::Checkpoint { height }
        }
        0x5343_4c54 => {
            if !(1..=3).contains(&body.read_u64(8)?) {
                return None;
            }
            let generation = body.read_u64(64)?;
            let height = body.read_u64(64)?;
            body.read_h256()?;
            body.read_h256()?;
            Progress::Latch { generation, height }
        }
        _ => return None,
    };
    body.exhausted().then_some(event)
}

fn read_array<const N: usize>(reader: &mut TonBitReader<'_>) -> Option<[u8; N]> {
    let mut out = [0; N];
    for byte in &mut out {
        *byte = u8::try_from(reader.read_u64(8)?).ok()?;
    }
    Some(out)
}

fn ordinary(boc: &TonBoc, index: usize) -> Option<TonBitReader<'_>> {
    let cell = boc.cells.get(index)?;
    (ton_cell_type(cell)? == TonCellType::Ordinary).then_some(())?;
    TonBitReader::new(cell)
}

fn certificate_body(boc: &TonBoc, mut body: TonBitReader<'_>) -> Option<Certificate> {
    if body.read_u64(32)? != 0x5343_4346 {
        return None;
    }
    let height = body.read_u64(64)?;
    let generation = body.read_u64(64)?;
    let mut cert = ordinary(boc, body.read_ref()?)?;
    body.exhausted().then_some(())?;
    let aggregate_signature = read_array(&mut cert)?;
    let signers: [u8; 4] = read_array(&mut cert)?;
    let mut qc_reader = ordinary(boc, cert.read_ref()?)?;
    let mut head = ordinary(boc, cert.read_ref()?)?;
    cert.exhausted().then_some(())?;
    let mut qc = [0; 116];
    qc[..112].copy_from_slice(&read_array::<112>(&mut qc_reader)?);
    qc[112..].copy_from_slice(&signers);
    qc_reader.exhausted().then_some(())?;
    let mut header = [0; 221];
    header[..109].copy_from_slice(&read_array::<109>(&mut head)?);
    let mut tail = ordinary(boc, head.read_ref()?)?;
    head.exhausted().then_some(())?;
    header[109..].copy_from_slice(&read_array::<112>(&mut tail)?);
    tail.exhausted().then_some(())?;
    let parsed = crate::v1::finality::SccpFinalityHeaderV1::parse(&header).ok()?;
    if parsed.height() != height || parsed.generation() != generation {
        return None;
    }
    Some(Certificate {
        qc,
        header,
        aggregate_signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ton::{BitsV1, CellArenaV1, LeafV1, hashmap_edge, key_bits};

    #[test]
    fn burn_discovery_binds_original_notification_query_and_wallet() {
        use crate::test_support::ton::{SyntheticTonChainV1, SyntheticTonEventV1};
        let minter = [7; 32];
        let wallet = [8; 32];
        let owner = [9; 32];
        let mut sender = vec![0; 4];
        sender.extend_from_slice(&owner);
        let payload = crate::v1::payload::SccpTransferPayloadV1::inbound(
            iroha_data_model::bridge::SccpNetworkV1::TonMainnet,
            17,
            1,
            1,
            sender,
            vec![3; 34],
        )
        .unwrap()
        .encode()
        .unwrap();
        let event = SyntheticTonEventV1::Transfer {
            message_id: [6; 32],
            nonce: 17,
            sender: owner,
            amount: 1,
            payload: payload.clone(),
        };
        for succeed in [true, false] {
            let (bytes, hash) = SyntheticTonChainV1::burn_transaction_boc(
                &minter, &wallet, 100, 19, &event, succeed,
            );
            let cursor = Cursor { lt: 100, hash };
            let mut observed = None;
            let result = burns(&bytes, &minter, cursor, |burn| {
                observed = Some(burn);
                true
            });
            if succeed {
                assert!(result.is_ok());
                assert_eq!(
                    observed,
                    Some(BurnObservation {
                        transaction: cursor,
                        message_index: 0,
                        query_id: 19,
                        notification_sender: wallet,
                        message_id: [6; 32],
                        nonce: 17,
                        owner,
                        amount: 1,
                        payload_hash: crate::v1::hashes::payload_hash(&payload)
                    })
                );
                assert_eq!(
                    burns(&bytes, &minter, cursor, |_| false),
                    Err(CertificatePageError::VisitorRefused)
                );
            } else {
                assert_eq!(result, Err(CertificatePageError::InvalidPage));
                assert!(observed.is_none());
            }
        }
    }

    #[test]
    fn terminal_discovery_requires_exact_successful_original_transaction() {
        use crate::test_support::ton::{SyntheticTonChainV1, SyntheticTonEventV1};
        let account = [0x42; 32];
        for (wire, expected) in [
            (
                SyntheticTonEventV1::Finalized {
                    message_id: [7; 32],
                    nonce: 19,
                },
                TerminalEvent::Finalized {
                    message_id: [7; 32],
                    nonce: 19,
                },
            ),
            (
                SyntheticTonEventV1::Voided {
                    message_id: [8; 32],
                    first_nonce: 20,
                    count: 1,
                },
                TerminalEvent::Voided {
                    message_id: [8; 32],
                    first_nonce: 20,
                    count: 1,
                },
            ),
        ] {
            for succeeds in [true, false] {
                let (bytes, hash) =
                    SyntheticTonChainV1::transaction_boc(&account, 100, &wire, succeeds);
                let cursor = Cursor { lt: 100, hash };
                let mut events = Vec::new();
                let result = terminal_events(&bytes, &account, cursor, |event| {
                    events.push(event);
                    true
                });
                if succeeds {
                    assert!(result.is_ok());
                    assert_eq!(
                        events,
                        vec![TerminalObservation {
                            transaction: cursor,
                            message_index: 0,
                            event: expected
                        }]
                    );
                    assert_eq!(
                        terminal_events(&bytes, &account, cursor, |_| false),
                        Err(CertificatePageError::VisitorRefused)
                    );
                    assert!(terminal_events(&bytes, &[9; 32], cursor, |_| true).is_err());
                    assert!(
                        terminal_events(
                            &bytes,
                            &account,
                            Cursor {
                                hash: [0; 32],
                                ..cursor
                            },
                            |_| true
                        )
                        .is_err()
                    );
                } else {
                    assert_eq!(result, Err(CertificatePageError::InvalidPage));
                    assert!(
                        events.is_empty(),
                        "a failed mint is never a finalized effect"
                    );
                }
            }
            let bytes = SyntheticTonChainV1::event_body_boc(&wire);
            let boc = parse_ton_boc(&bytes).unwrap();
            assert_eq!(
                terminal_body(ordinary(&boc, boc.roots[0]).unwrap()),
                Some(expected)
            );
        }
    }

    #[test]
    fn published_ton_certificate_preserves_exact_wire_and_rejects_identity_changes() {
        let fixture: norito::json::Value =
            norito::json::from_str(include_str!("../../../../fixtures/sccp/finality_v1.json"))
                .unwrap();
        let fixture = &fixture["certificates"][0];
        let bytes = |field: &str| {
            crate::test_support::ethereum::hex_bytes(fixture["evm"][field].as_str().unwrap())
        };
        let x = bytes("header");
        let qc = bytes("qc");
        let signature = crate::test_support::ethereum::hex_bytes(
            fixture["aggregate_signature"]["compressed"]
                .as_str()
                .unwrap(),
        );
        let parsed = crate::v1::finality::SccpFinalityHeaderV1::parse(&x).unwrap();
        let mut arena = CellArenaV1::new();
        let tail = arena.cell(BitsV1::new().bytes(&x[109..]), &[]);
        let head = arena.cell(BitsV1::new().bytes(&x[..109]), &[tail]);
        let qc_cell = arena.cell(BitsV1::new().bytes(&qc[..112]), &[]);
        let cert = arena.cell(
            BitsV1::new().bytes(&signature).bytes(&qc[112..]),
            &[qc_cell, head],
        );
        let event = arena.cell(
            BitsV1::new()
                .uint(0x5343_4346, 32)
                .uint(parsed.height().into(), 64)
                .uint(parsed.generation().into(), 64),
            &[cert],
        );
        let boc = parse_ton_boc(&arena.boc(event)).unwrap();
        let decoded = certificate_body(&boc, ordinary(&boc, boc.roots[0]).unwrap()).unwrap();
        assert_eq!(decoded.header.as_slice(), x);
        assert_eq!(decoded.qc.as_slice(), qc);
        assert_eq!(decoded.aggregate_signature.as_slice(), signature);
        let account = [0x71; 32];
        let message = arena.cell(
            BitsV1::new()
                .uint(0b11, 2)
                .std_address(0, &account)
                .uint(0, 2)
                .uint(100, 64)
                .uint(1, 32)
                .bit(false)
                .bit(true),
            &[event],
        );
        let messages = hashmap_edge(
            &mut arena,
            &[(
                key_bits(&0_u16.to_be_bytes(), 15),
                LeafV1 {
                    bits: BitsV1::new(),
                    refs: vec![message],
                },
            )],
            15,
            None,
        );
        let messages = arena.cell(&messages.bits, &messages.refs);
        let auxiliary = arena.cell(BitsV1::new().bit(false).bit(true), &[messages]);
        let update = arena.cell(
            BitsV1::new().uint(0x72, 8).bytes(&[1; 32]).bytes(&[2; 32]),
            &[],
        );
        let description = arena.cell(&BitsV1::new(), &[]);
        let tx = arena.cell(
            BitsV1::new()
                .uint(7, 4)
                .bytes(&account)
                .uint(100, 64)
                .bytes(&[0; 32])
                .uint(0, 64)
                .uint(1, 32)
                .uint(1, 15)
                .uint(2, 2)
                .uint(2, 2)
                .zero_currency(),
            &[auxiliary, update, description],
        );
        let cursor = Cursor {
            lt: 100,
            hash: arena.hash(tx),
        };
        let transaction = arena.boc(tx);
        let mut visited = 0;
        assert_eq!(
            certificates(
                &transaction,
                &account,
                cursor,
                |certificate| {
                    assert_eq!(certificate, decoded);
                    visited += 1;
                    true
                },
                |_| panic!("only certificate")
            ),
            Ok(None)
        );
        assert_eq!(visited, 1);
        assert_eq!(
            certificates(&transaction, &[9; 32], cursor, |_| true, |_| {}),
            Err(CertificatePageError::InvalidPage)
        );
        assert!(
            certificates(
                &transaction,
                &account,
                Cursor {
                    hash: [0; 32],
                    ..cursor
                },
                |_| true,
                |_| {}
            )
            .is_err()
        );
        assert_eq!(
            certificates(&transaction, &account, cursor, |_| false, |_| {}),
            Err(CertificatePageError::VisitorRefused)
        );
        let wrong = arena.cell(
            BitsV1::new()
                .uint(0x5343_4346, 32)
                .uint((parsed.height() + 1).into(), 64)
                .uint(parsed.generation().into(), 64),
            &[cert],
        );
        let boc = parse_ton_boc(&arena.boc(wrong)).unwrap();
        assert!(certificate_body(&boc, ordinary(&boc, boc.roots[0]).unwrap()).is_none());
    }

    #[test]
    fn account_cursor_selects_exact_shard_account_and_progress_has_exact_shape() {
        let mut arena = CellArenaV1::new();
        let account = [7; 32];
        let hash = [8; 32];
        let empty = arena.cell(&BitsV1::new(), &[]);
        let mut data = BitsV1::new();
        data.uint(0, 5).zero_currency().bytes(&hash).uint(123, 64);
        let leaf = LeafV1 {
            bits: data,
            refs: vec![empty],
        };
        let edge = hashmap_edge(&mut arena, &[(key_bits(&account, 256), leaf)], 256, None);
        let edge = arena.cell(&edge.bits, &edge.refs);
        let accounts = arena.cell(BitsV1::new().bit(true).uint(0, 5).zero_currency(), &[edge]);
        let mut bits = BitsV1::new();
        bits.uint(u128::from(TON_SHARD_STATE_CONSTRUCTOR), 32)
            .int(-239, 32)
            .shard_ident(0)
            .uint(0, 32)
            .uint(0, 32)
            .uint(0, 32)
            .uint(0, 64)
            .uint(0, 32)
            .bit(false)
            .bit(false);
        let state = arena.cell(&bits, &[empty, accounts, empty]);
        let proof = arena.boc(state);
        assert_eq!(
            account_cursor(&proof, &account),
            Some(Cursor { lt: 123, hash })
        );
        assert_eq!(account_cursor(&proof, &[9; 32]), None);
        assert_eq!(account_cursor(&proof[..proof.len() - 1], &account), None);
        let rotation = arena.cell(
            BitsV1::new()
                .uint(0x5343_5252, 32)
                .uint(8, 64)
                .bytes(&[3; 32])
                .uint(99, 64)
                .uint(10, 64),
            &[],
        );
        let boc = parse_ton_boc(&arena.boc(rotation)).unwrap();
        assert_eq!(
            progress_body(ordinary(&boc, boc.roots[0]).unwrap()),
            Some(Progress::Rotation {
                generation: 8,
                until_ms: 99
            })
        );
        assert!(
            certificates(
                &proof,
                &account,
                Cursor { lt: 123, hash },
                |_| panic!("not a transaction"),
                |_| {}
            )
            .is_err()
        );
    }
}
