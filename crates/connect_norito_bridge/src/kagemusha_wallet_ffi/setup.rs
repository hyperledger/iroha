//! Typed setup input shared by C/JNI; no foreign clock or arbitrary signature body.

use super::*;

pub(crate) enum Setup {
    Bootstrap,
    ReviewCustodyDeletion,
    ConfirmCustodyDeletion {
        token: u64,
    },
    ResumeCustodyDeletion,
    DiscardCustodyDeletion {
        token: u64,
    },
    CollectRetained {
        sequence: u128,
    },
    RequestFeeSelection,
    ValidateRequestFeePolicy {
        schedule: Vec<u8>,
        certificates: Vec<u8>,
    },
    RequestWithFeePolicy {
        id: [u8; 32],
        offer: Vec<u8>,
        schedule: Vec<u8>,
        certificates: Vec<u8>,
    },
    UnloadClaim {
        request_id: [u8; 32],
        beneficiary: Option<Vec<u8>>,
    },
    FeeClaim {
        credit: [u8; 32],
    },
    FeeOriginal {
        request: bool,
        original: Vec<u8>,
    },
    FeeClaimTransport {
        original: Vec<u8>,
        beneficiary: Vec<u8>,
    },
    LedgerLoad {
        id: [u8; 32],
        amount: u128,
    },
    LedgerInstruction {
        kind: u64,
        original: Vec<u8>,
    },
    ConfirmUnload {
        transaction: [u8; 32],
        original: Vec<u8>,
    },
    UnloadProofProgress {
        transaction: [u8; 32],
        original: Vec<u8>,
    },
    UnloadProofStep {
        transaction: [u8; 32],
        original: Vec<u8>,
        finality: Vec<u8>,
    },
    ConfirmActivation(Vec<u8>),
    RetainActivationAttempt(Vec<u8>),
    ActivationProofProgress(Vec<u8>),
    ActivationProofStep {
        signed: Vec<u8>,
        original: Vec<u8>,
    },
    LedgerFinality(Vec<u8>),
    LedgerStatus,
    EpochStatus,
    EpochBoundary {
        epoch: u64,
        original: Vec<u8>,
    },
    FeePayout {
        credit: [u8; 32],
        world: Vec<u8>,
        payout: Vec<u8>,
    },
    BackgroundStatus,
    Activation,
    CloseLoads {
        id: [u8; 32],
    },
    Transport {
        kind: u8,
        wrap: bool,
        original: Vec<u8>,
    },
    Offer {
        id: [u8; 32],
        amount: u128,
    },
    Request {
        id: [u8; 32],
        offer: Vec<u8>,
        fee: Option<
            Box<(
                KagemushaWalletFeeScheduleV1,
                KagemushaWalletSignerCertificateV1,
            )>,
        >,
    },
    Credited(Vec<u8>),
    BoundCredited {
        send_request: [u8; 32],
        original: Vec<u8>,
        query: bool,
    },
    CreditProjection {
        id: [u8; 32],
        anchor: Vec<u8>,
        newer: Vec<u8>,
    },
    CreditedOriginal {
        status: bool,
        original: Vec<u8>,
    },
    BeginTime,
    CancelTime {
        token: u64,
    },
    FinishTime {
        token: u64,
        anchor: Vec<u8>,
        certificate: Vec<u8>,
    },
}
fn activation_progress(value: state::ActivationFinalityProgressV1) -> Response {
    let (kind, progress) = match value {
        state::ActivationFinalityProgressV1::Confirmed(progress) => (44, Some(progress)),
        state::ActivationFinalityProgressV1::Verifying(progress) => (45, Some(progress)),
        state::ActivationFinalityProgressV1::Rejected(progress) => (49, Some(progress)),
        state::ActivationFinalityProgressV1::NotStarted => (46, None),
    };
    let mut response = ledger_progress(progress);
    response.kind = kind;
    response
}
fn unload_progress(value: state::UnloadFinalityProgressV1) -> Response {
    let (kind, progress) = match value {
        state::UnloadFinalityProgressV1::Confirmed(progress) => (42, Some(progress)),
        state::UnloadFinalityProgressV1::Verifying(progress) => (33, Some(progress)),
        state::UnloadFinalityProgressV1::NotStarted => (34, None),
    };
    let mut response = ledger_progress(progress);
    response.kind = kind;
    response
}
pub(crate) fn bounds(selector: u32) -> Result<[usize; 3]> {
    Ok(match selector {
        43 | 47 | 48 | 49 | 50 | 51 | 52 => [0; 3],
        53 => [
            iroha_data_model::sumeragi_finality::MAX_COMMIT_CERTIFICATE_BYTES_V1,
            0,
            0,
        ],
        44 => [
            KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
            KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
            0,
        ],
        0 | 1 | 4 | 6 | 15 | 18 | 19 | 20 | 24 | 27 | 38 => [0; 3],
        39 => [KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1; 3],
        40 => [
            KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
            KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
            0,
        ],
        35 | 37 | 46 => [state::LEDGER_INSTRUCTION_MAX_BYTES_V1, 0, 0],
        36 => [
            state::LEDGER_INSTRUCTION_MAX_BYTES_V1,
            state::LEDGER_PROOF_MAX_BYTES_V1,
            0,
        ],
        34 => [
            state::LEDGER_INSTRUCTION_MAX_BYTES_V1,
            state::LEDGER_PROOF_MAX_BYTES_V1,
            0,
        ],
        29 | 30 | 33 => [state::LEDGER_INSTRUCTION_MAX_BYTES_V1, 0, 0],
        21 | 22 => [state::FEE_CLAIM_MAX_BYTES_V1, 0, 0],
        23 => [state::LEDGER_PROOF_MAX_BYTES_V1, 0, 0],
        45 => [KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1, 0, 0],
        26 => [
            state::FEE_CLAIM_MAX_BYTES_V1,
            KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1,
            0,
        ],
        25 => [
            iroha_data_model::sumeragi_finality::MAX_WORLD_STATE_SNAPSHOT_BYTES_V1,
            state::PAYOUT_RECORD_MAX_BYTES_V1,
            0,
        ],
        2 => [
            KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
            KAGEMUSHA_WALLET_FEE_SCHEDULE_MAX_BYTES_V1,
            KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
        ],
        3 | 7..=14 | 16..=17 | 41..=42 => [KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1, 0, 0],
        5 => [
            KAGEMUSHA_WALLET_TIME_ANCHOR_MAX_BYTES_V1,
            KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
            0,
        ],
        _ => return Err(Failure::code(INVALID)),
    })
}
fn decode<T>(bytes: &[u8]) -> Result<T>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))
        .map_err(|_| Failure::code(INVALID))
}
pub(crate) fn request(
    id: &[u8],
    selector: u32,
    amount: u128,
    token: u64,
    originals: [&[u8]; 3],
) -> Result<Setup> {
    let id: [u8; 32] = id.try_into().map_err(|_| Failure::code(INVALID))?;
    let bounds = bounds(selector)?;
    if (matches!(
        selector,
        1 | 2 | 19 | 20 | 25 | 27 | 30 | 33 | 34 | 39 | 41 | 42 | 43 | 44 | 45
    ) != (id != [0; 32]))
        || (!matches!(selector, 47 | 53) && (matches!(selector, 1 | 27) != (amount != 0)))
        || (selector == 53 && amount > u128::from(u64::MAX))
        || (matches!(selector, 5 | 6 | 29 | 49 | 51) != (token != 0))
        || (selector == 29 && !(1..=3).contains(&token))
        || originals
            .iter()
            .zip(bounds)
            .any(|(bytes, bound)| bytes.len() > bound)
    {
        return Err(Failure::code(INVALID));
    }
    let [first, second, third] = originals;
    Ok(match selector {
        0 => Setup::Bootstrap,
        48 => Setup::ReviewCustodyDeletion,
        49 => Setup::ConfirmCustodyDeletion { token },
        50 => Setup::ResumeCustodyDeletion,
        51 => Setup::DiscardCustodyDeletion { token },
        52 => Setup::EpochStatus,
        53 if !first.is_empty() => Setup::EpochBoundary {
            epoch: amount as u64,
            original: first.to_vec(),
        },
        47 => Setup::CollectRetained { sequence: amount },
        38 => Setup::RequestFeeSelection,
        39 if !first.is_empty() && second.is_empty() == third.is_empty() => {
            Setup::RequestWithFeePolicy {
                id,
                offer: first.to_vec(),
                schedule: second.to_vec(),
                certificates: third.to_vec(),
            }
        }
        40 if !first.is_empty() && !second.is_empty() => Setup::ValidateRequestFeePolicy {
            schedule: first.to_vec(),
            certificates: second.to_vec(),
        },
        45 => Setup::UnloadClaim {
            request_id: id,
            beneficiary: (!first.is_empty()).then(|| first.to_vec()),
        },
        20 => Setup::FeeClaim { credit: id },
        21 | 22 if !first.is_empty() => Setup::FeeOriginal {
            request: selector == 22,
            original: first.to_vec(),
        },
        27 => Setup::LedgerLoad { id, amount },
        29 if !first.is_empty() => Setup::LedgerInstruction {
            kind: token,
            original: first.to_vec(),
        },
        30 if !first.is_empty() => Setup::ConfirmUnload {
            transaction: id,
            original: first.to_vec(),
        },
        33 if !first.is_empty() => Setup::UnloadProofProgress {
            transaction: id,
            original: first.to_vec(),
        },
        34 if !first.is_empty() && !second.is_empty() => Setup::UnloadProofStep {
            transaction: id,
            original: first.to_vec(),
            finality: second.to_vec(),
        },
        35 if !first.is_empty() => Setup::ConfirmActivation(first.to_vec()),
        36 if !first.is_empty() && !second.is_empty() => Setup::ActivationProofStep {
            signed: first.to_vec(),
            original: second.to_vec(),
        },
        37 if !first.is_empty() => Setup::ActivationProofProgress(first.to_vec()),
        46 if !first.is_empty() => Setup::RetainActivationAttempt(first.to_vec()),
        23 if !first.is_empty() => Setup::LedgerFinality(first.to_vec()),
        24 => Setup::LedgerStatus,
        26 if !first.is_empty() && !second.is_empty() => Setup::FeeClaimTransport {
            original: first.to_vec(),
            beneficiary: second.to_vec(),
        },
        25 if !first.is_empty() && !second.is_empty() => Setup::FeePayout {
            credit: id,
            world: first.to_vec(),
            payout: second.to_vec(),
        },
        15 => Setup::Activation,
        18 => Setup::BackgroundStatus,
        19 => Setup::CloseLoads { id },
        1 => Setup::Offer { id, amount },
        2 if !first.is_empty() && second.is_empty() == third.is_empty() => Setup::Request {
            id,
            offer: first.to_vec(),
            fee: if second.is_empty() {
                None
            } else {
                Some(Box::new((decode(second)?, decode(third)?)))
            },
        },
        3 if !first.is_empty() => Setup::Credited(first.to_vec()),
        41..=42 if !first.is_empty() => Setup::BoundCredited {
            send_request: id,
            original: first.to_vec(),
            query: selector == 42,
        },
        43 => Setup::CreditProjection {
            id,
            anchor: Vec::new(),
            newer: Vec::new(),
        },
        44 if !first.is_empty() => Setup::CreditProjection {
            id,
            anchor: first.to_vec(),
            newer: second.to_vec(),
        },
        16..=17 if !first.is_empty() => Setup::CreditedOriginal {
            status: selector == 17,
            original: first.to_vec(),
        },
        4 => Setup::BeginTime,
        6 => Setup::CancelTime { token },
        7..=14 if !first.is_empty() => Setup::Transport {
            kind: ((selector - 7) % 4 + 1) as u8,
            wrap: selector < 11,
            original: first.to_vec(),
        },
        5 if !first.is_empty() && !second.is_empty() => Setup::FinishTime {
            token,
            // Decode only after the same owner's one-use exchange has been consumed.
            anchor: first.to_vec(),
            certificate: second.to_vec(),
        },
        _ => return Err(Failure::code(INVALID)),
    })
}
fn take_time<T>(times: &mut BTreeMap<u64, T>, token: u64) -> Result<T> {
    times.remove(&token).ok_or(Failure::code(INVALID))
}
fn take_time_response<T>(
    times: &mut BTreeMap<u64, T>,
    token: u64,
    anchor: &[u8],
    certificate: &[u8],
) -> Result<(
    T,
    KagemushaWalletTimeAnchorV1,
    KagemushaWalletSignerCertificateV1,
)> {
    // Malformed response bytes must retire the exchange too: the SDK has already
    // consumed its token, so leaving this entry live would make it unreachable.
    let exchange = take_time(times, token)?;
    Ok((exchange, decode(anchor)?, decode(certificate)?))
}
fn ledger_progress(progress: Option<state::LedgerProgressV1>) -> Response {
    match progress {
        Some(progress) => Response {
            kind: 33,
            sequence: u128::from(progress.height),
            bytes: progress.block_hash.to_vec(),
            ..Response::default()
        },
        None => Response {
            kind: 34,
            ..Response::default()
        },
    }
}
fn epoch_progress(progress: state::NativeEpochProgressV1) -> Response {
    Response {
        kind: 57,
        sequence: u128::from(progress.epoch),
        bytes: [
            progress.first_height.to_le_bytes(),
            progress.boundary_height.to_le_bytes(),
        ]
        .concat(),
        ..Response::default()
    }
}
impl<P, S> NativeWallet<P, S>
where
    P: advance::KagemushaWalletPlatformV1,
    S: OriginalSourceV1 + Send,
{
    pub(super) fn setup_inner(&mut self, input: Setup) -> Result<Response> {
        let bytes = match input {
            Setup::RequestFeeSelection => {
                let (asset, fee) = self.wallet.request_fee_selection()?;
                [asset.as_slice(), fee.as_slice()].concat()
            }
            Setup::ValidateRequestFeePolicy {
                schedule,
                certificates,
            } => {
                let (asset, fee) = self
                    .wallet
                    .validate_request_fee_policy(&schedule, &certificates)?;
                [asset.as_slice(), fee.as_slice()].concat()
            }
            Setup::RequestWithFeePolicy {
                id,
                offer,
                schedule,
                certificates,
            } => self
                .wallet
                .request_with_fee_policy(id, &offer, &schedule, &certificates)?,
            Setup::UnloadClaim {
                request_id,
                beneficiary,
            } => {
                return Ok(Response {
                    kind: 48,
                    bytes: self
                        .wallet
                        .unload_claim_bytes(&request_id, beneficiary.as_deref())?,
                    ..Response::default()
                });
            }
            Setup::FeeClaim { credit } => {
                let original = self.wallet.fee_claim(credit)?;
                return Ok(match original {
                    None => Response {
                        kind: 32,
                        ..Response::default()
                    },
                    Some(original) => Response {
                        kind: 31,
                        bytes: original.to_canonical_bytes(&self.wallet.snapshot()?.scheme_id)?,
                        ..Response::default()
                    },
                });
            }
            Setup::FeeOriginal { request, original } => {
                let claim = state::RetainedFeeClaim::decode_canonical(
                    &original,
                    &self.wallet.snapshot()?.scheme_id,
                )?;
                if request {
                    claim.request
                } else {
                    claim.payment
                }
            }
            Setup::FeeClaimTransport {
                original,
                beneficiary,
            } => {
                let scheme = self.wallet.snapshot()?.scheme_id;
                let claim = state::RetainedFeeClaim::decode_canonical(&original, &scheme)?;
                return Ok(Response {
                    kind: 36,
                    bytes: claim.ledger_claim_bytes(&scheme, &beneficiary)?,
                    ..Response::default()
                });
            }
            Setup::LedgerLoad { id, amount } => {
                return Ok(Response {
                    kind: 40,
                    bytes: self.wallet.prepare_ledger_load(id, amount)?,
                    ..Response::default()
                });
            }
            Setup::LedgerInstruction { kind, original } => {
                return Ok(Response {
                    kind: 40,
                    bytes: self.wallet.ledger_instruction(kind, &original)?,
                    ..Response::default()
                });
            }
            Setup::ConfirmUnload {
                transaction,
                original,
            } => {
                let mut response = ledger_progress(Some(
                    self.wallet.confirm_ledger_unload(transaction, &original)?,
                ));
                response.kind = 42;
                return Ok(response);
            }
            Setup::UnloadProofProgress {
                transaction,
                original,
            } => {
                return Ok(unload_progress(
                    self.wallet
                        .unload_finality_progress(transaction, &original)?,
                ));
            }
            Setup::UnloadProofStep {
                transaction,
                original,
                finality,
            } => {
                return Ok(ledger_progress(Some(self.wallet.ingest_unload_finality(
                    transaction,
                    &original,
                    &finality,
                )?)));
            }
            Setup::ConfirmActivation(signed) => {
                return Ok(activation_progress(
                    state::ActivationFinalityProgressV1::Confirmed(
                        self.wallet.confirm_ledger_activation(&signed)?,
                    ),
                ));
            }
            Setup::RetainActivationAttempt(signed) => {
                return Ok(activation_progress(
                    self.wallet.retain_activation_attempt(&signed)?,
                ));
            }
            Setup::ActivationProofProgress(signed) => {
                return Ok(activation_progress(
                    self.wallet.activation_finality_progress(&signed)?,
                ));
            }
            Setup::ActivationProofStep { signed, original } => {
                return Ok(activation_progress(
                    self.wallet.ingest_activation_finality(&signed, &original)?,
                ));
            }
            Setup::LedgerFinality(original) => {
                return Ok(ledger_progress(Some(
                    self.wallet.ingest_ledger_finality(&original)?,
                )));
            }
            Setup::LedgerStatus => return Ok(ledger_progress(self.wallet.ledger_progress()?)),
            Setup::EpochStatus => return Ok(epoch_progress(self.wallet.epoch_progress()?)),
            Setup::EpochBoundary { epoch, original } => {
                return Ok(epoch_progress(
                    self.wallet.ingest_epoch_boundary(epoch, &original)?,
                ));
            }
            Setup::FeePayout {
                credit,
                world,
                payout,
            } => {
                self.wallet
                    .acknowledge_fee_payout_originals(credit, &world, &payout)?;
                return Ok(Response {
                    kind: 35,
                    ..Response::default()
                });
            }
            Setup::Transport {
                kind,
                wrap,
                original,
            } => {
                // Framing/extraction validates representation and scheme, not wallet readiness.
                let scheme = self.wallet.transport_scheme_id()?;
                transport::convert(kind, wrap, &original, &scheme)?
            }
            Setup::CreditedOriginal { status, original } => {
                // Encoding retained bytes needs the admitted scheme and live custody, not a
                // balance/fold snapshot. The codec still validates its full canonical carrier.
                let scheme = self.wallet.transport_scheme_id()?;
                transport::credited(status, &original, &scheme)?
            }
            Setup::BackgroundStatus => return Err(Failure::code(INTERNAL)),
            Setup::CollectRetained { sequence } => {
                let (kind, sequence) = match self.wallet.collect_retained_step(sequence)? {
                    state::CollectionStatus::Idle => (50, 0),
                    state::CollectionStatus::Progress(sequence) => (51, sequence),
                    state::CollectionStatus::Collected(sequence) => (52, sequence),
                };
                return Ok(Response {
                    kind,
                    sequence,
                    ..Response::default()
                });
            }
            Setup::ReviewCustodyDeletion => return self.review_deletion(),
            Setup::ConfirmCustodyDeletion { token } => return self.confirm_deletion(token),
            Setup::ResumeCustodyDeletion => return self.resume_deletion(),
            Setup::DiscardCustodyDeletion { token } => return self.discard_deletion(token),
            Setup::Bootstrap => return completion(Some(self.wallet.bootstrap()?)),
            Setup::CloseLoads { id } => {
                return Ok(Response {
                    kind: 30,
                    bytes: self.wallet.close_loads(id)?,
                    ..Response::default()
                });
            }
            Setup::Activation => {
                return Ok(Response {
                    kind: 17,
                    bytes: self.wallet.activation()?,
                    ..Response::default()
                });
            }
            Setup::Offer { id, amount } => self.wallet.offer(id, amount)?,
            Setup::Request { id, offer, fee } => {
                let fee = fee.map(|value| *value);
                self.wallet.request(id, &offer, fee.as_ref())?
            }
            Setup::Credited(bytes) => {
                return completion(Some(self.wallet.accept_credited(&bytes)?));
            }
            Setup::BoundCredited {
                send_request,
                original,
                query,
            } => {
                return Ok(if query {
                    match self
                        .wallet
                        .credited_status_for_send(&send_request, &original)?
                    {
                        state::RequestStatusV1::Unknown => Response::default(),
                        state::RequestStatusV1::Preparing => Response {
                            kind: 11,
                            ..Response::default()
                        },
                        state::RequestStatusV1::Outcome(value) => completion(Some(value))?,
                    }
                } else {
                    completion(Some(
                        self.wallet
                            .accept_credited_for_send(&send_request, &original)?,
                    ))?
                });
            }
            Setup::CreditProjection { id, anchor, newer } => {
                return Ok(Response {
                    kind: 47,
                    bytes: if anchor.is_empty() {
                        self.wallet.receive_credit_projection(&id)?.bytes()
                    } else {
                        self.wallet
                            .delivery_credit_projection(&id, &anchor, &newer)?
                            .bytes()
                    },
                    ..Response::default()
                });
            }
            Setup::BeginTime => {
                if self.times.len() >= 32 {
                    return Err(Failure::code(RESOURCE));
                }
                let token = review::allocate_token()?;
                let exchange = self.wallet.begin_direct_time_exchange()?;
                let nonce = exchange.nonce().to_vec();
                self.times.insert(token, exchange);
                return Ok(Response {
                    kind: 13,
                    sequence: u128::from(token),
                    bytes: nonce,
                    ..Response::default()
                });
            }
            Setup::CancelTime { token } => {
                take_time(&mut self.times, token)?;
                return Ok(Response {
                    kind: 6,
                    ..Response::default()
                });
            }
            Setup::FinishTime {
                token,
                anchor,
                certificate,
            } => {
                let (exchange, anchor, certificate) =
                    take_time_response(&mut self.times, token, &anchor, &certificate)?;
                self.wallet
                    .finish_direct_time_exchange(exchange, anchor, &certificate)?;
                return Ok(Response {
                    kind: 14,
                    ..Response::default()
                });
            }
        };
        Ok(Response {
            kind: 12,
            bytes,
            ..Response::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_ingress_has_one_bounded_original_and_no_authority_fields() {
        let zero = [0; 32];
        assert!(matches!(
            request(&zero, 52, 0, 0, [&[]; 3]),
            Ok(Setup::EpochStatus)
        ));
        assert_eq!(bounds(53).unwrap(), [262_144, 0, 0]);
        for epoch in [0, u128::from(u64::MAX)] {
            assert!(matches!(request(&zero, 53, epoch, 0, [&[7], &[], &[]]),
                Ok(Setup::EpochBoundary { epoch: selected, original }) if u128::from(selected) == epoch && original == [7]));
        }
        assert!(request(&zero, 53, u128::from(u64::MAX) + 1, 0, [&[7], &[], &[]]).is_err());
        assert!(request(&zero, 53, 0, 0, [&[]; 3]).is_err());
        assert!(request(&zero, 53, 0, 0, [&vec![1; 262_145], &[], &[]]).is_err());
        for selector in [52, 53] {
            let first: &[u8] = if selector == 53 { &[1] } else { &[] };
            assert!(request(&[1; 32], selector, 0, 0, [first, &[], &[]]).is_err());
            assert!(request(&zero, selector, 0, 1, [first, &[], &[]]).is_err());
            assert!(request(&zero, selector, 0, 0, [first, &[1], &[]]).is_err());
            assert!(request(&zero, selector, 0, 0, [first, &[], &[1]]).is_err());
        }
        let result = epoch_progress(state::NativeEpochProgressV1 {
            epoch: u64::MAX,
            first_height: 4,
            boundary_height: u64::MAX,
        });
        assert_eq!(result.kind, 57);
        assert_eq!(result.sequence, u128::from(u64::MAX));
        assert_eq!(result.detail, 0);
        assert_eq!(
            result.bytes,
            [4u64.to_le_bytes(), u64::MAX.to_le_bytes()].concat()
        );
    }

    #[test]
    fn unload_settlement_union_preserves_native_confirmation_and_absence() {
        let progress = state::LedgerProgressV1 {
            height: 2,
            block_hash: [7; 32],
        };
        let absent = unload_progress(state::UnloadFinalityProgressV1::NotStarted);
        assert_eq!(absent.kind, 34);
        assert!(absent.bytes.is_empty());
        let verifying = unload_progress(state::UnloadFinalityProgressV1::Verifying(progress));
        assert_eq!(verifying.kind, 33);
        assert_eq!(verifying.bytes, [7; 32]);
        let confirmed = unload_progress(state::UnloadFinalityProgressV1::Confirmed(progress));
        assert_eq!(confirmed.kind, 42);
        assert_eq!(confirmed.bytes, [7; 32]);
    }
    #[test]
    fn credit_projection_intake_has_exact_role_bounds_and_no_foreign_authority() {
        let id = [7; 32];
        let zero = [0; 32];
        let one: &[u8] = &[1];
        let empty: &[u8] = &[];
        assert!(request(&id, 43, 0, 0, [empty; 3]).is_ok());
        assert!(request(&id, 44, 0, 0, [one, empty, empty]).is_ok());
        assert!(request(&id, 44, 0, 0, [one, one, empty]).is_ok());
        assert!(request(&id, 43, 0, 0, [one, empty, empty]).is_err());
        assert!(request(&id, 44, 0, 0, [empty, one, empty]).is_err());
        assert!(request(&id, 44, 0, 0, [one; 3]).is_err());
        for selector in [43, 44] {
            let inputs = if selector == 43 {
                [empty; 3]
            } else {
                [one, one, empty]
            };
            assert!(request(&zero, selector, 0, 0, inputs).is_err());
            assert!(request(&id, selector, 1, 0, inputs).is_err());
            assert!(request(&id, selector, 0, 1, inputs).is_err());
        }
        for index in [0, 1] {
            let oversized = vec![0; 10_001];
            let mut inputs = [one, one, empty];
            inputs[index] = &oversized;
            assert!(request(&id, 44, 0, 0, inputs).is_err());
        }
    }
    #[test]
    fn bound_delivery_intake_requires_exact_send_identity_and_bounded_original() {
        let id = [7; 32];
        let zero = [0; 32];
        let one: &[u8] = &[1];
        let empty: &[u8] = &[];
        for selector in [41, 42] {
            let value = request(&id, selector, 0, 0, [one, empty, empty]).unwrap();
            assert!(
                matches!(value, Setup::BoundCredited { send_request, original, query } if send_request == id && original == one && query == (selector == 42))
            );
            assert!(request(&zero, selector, 0, 0, [one, empty, empty]).is_err());
            assert!(request(&id, selector, 0, 0, [empty; 3]).is_err());
            assert!(request(&id, selector, 1, 0, [one, empty, empty]).is_err());
            assert!(request(&id, selector, 0, 1, [one, empty, empty]).is_err());
            assert!(request(&id, selector, 0, 0, [one; 3]).is_err());
            assert!(request(&id, selector, 0, 0, [&vec![0; 10_001], empty, empty]).is_err());
        }
    }
    #[test]
    fn fee_policy_intake_bounds_pairing_and_unused_authority_fields() {
        let zero = [0; 32];
        let id = [7; 32];
        let one: &[u8] = &[1];
        let empty: &[u8] = &[];
        assert!(matches!(
            request(&zero, 38, 0, 0, [empty; 3]).unwrap(),
            Setup::RequestFeeSelection
        ));
        for selector in [38, 40] {
            let originals = if selector == 40 {
                [one, one, empty]
            } else {
                [empty; 3]
            };
            assert!(request(&zero, selector, 0, 0, originals).is_ok());
            assert!(request(&id, selector, 0, 0, originals).is_err());
            assert!(request(&zero, selector, 1, 0, originals).is_err());
            assert!(request(&zero, selector, 0, 1, originals).is_err());
        }
        assert!(request(&id, 39, 0, 0, [one, empty, empty]).is_ok());
        assert!(request(&id, 39, 0, 0, [one; 3]).is_ok());
        assert!(request(&id, 39, 0, 0, [one, one, empty]).is_err());
        assert!(request(&id, 39, 0, 0, [one, empty, one]).is_err());
        assert!(request(&zero, 39, 0, 0, [one; 3]).is_err());
        assert!(request(&id, 39, 0, 0, [empty, one, one]).is_err());
        assert!(request(&zero, 40, 0, 0, [one, empty, empty]).is_err());
        assert!(request(&zero, 40, 0, 0, [one; 3]).is_err());
        for index in 0..3 {
            let oversized = vec![0; 10_001];
            let mut inputs = [one; 3];
            inputs[index] = &oversized;
            assert!(request(&id, 39, 0, 0, inputs).is_err());
        }
    }
    #[test]
    fn collection_intake_accepts_only_a_sequence_and_no_foreign_authority() {
        for sequence in [0, 1, u128::MAX] {
            assert!(
                matches!(request(&[0; 32], 47, sequence, 0, [&[]; 3]).unwrap(),
                Setup::CollectRetained { sequence: value } if value == sequence)
            );
            assert!(request(&[1; 32], 47, sequence, 0, [&[]; 3]).is_err());
            assert!(request(&[0; 32], 47, sequence, 1, [&[]; 3]).is_err());
            for index in 0..3 {
                let mut originals: [&[u8]; 3] = [&[]; 3];
                originals[index] = &[1];
                assert!(request(&[0; 32], 47, sequence, 0, originals).is_err());
            }
        }
        assert!(bounds(54).is_err());
    }

    #[test]
    fn setup_intake_rejects_unused_authority_fields_and_wrong_bounds() {
        for selector in [0, 1, 3, 4, 15, 18, 19] {
            let id = if matches!(selector, 1 | 19) {
                [1; 32]
            } else {
                [0; 32]
            };
            let amount = if selector == 1 { u128::MAX } else { 0 };
            let first: &[u8] = if selector == 3 { &[7] } else { &[] };
            assert!(request(&id, selector, amount, 0, [first, &[], &[]]).is_ok());
            assert!(request(&id, selector, amount, 1, [first, &[], &[]]).is_err());
            assert!(request(&id, selector, amount, 0, [first, &[7], &[]]).is_err());
        }
        assert!(request(&[1; 32], 2, 0, 0, [&[7], &[], &[]]).is_ok());
        assert!(request(&[1; 32], 2, 0, 0, [&[7], &[7], &[]]).is_err());
        assert!(request(&[0; 32], 2, 0, 0, [&[7], &[], &[]]).is_err());
        assert!(request(&[1; 31], 1, 1, 0, [&[]; 3]).is_err());
        assert!(request(&[0; 32], 5, 0, 1, [&[]; 3]).is_err());
        assert!(request(&[0; 32], 6, 0, 1, [&[]; 3]).is_ok());
        assert!(request(&[0; 32], 6, 0, 0, [&[]; 3]).is_err());
        assert!(request(&[1; 32], 6, 0, 1, [&[]; 3]).is_err());
        assert!(request(&[0; 32], 6, 1, 1, [&[]; 3]).is_err());
        assert!(request(&[0; 32], 6, 0, 1, [&[7], &[], &[]]).is_err());
        for selector in (7..=14).chain(16..=17) {
            assert!(request(&[0; 32], selector, 0, 0, [&[7], &[], &[]]).is_ok());
            assert!(request(&[0; 32], selector, 0, 0, [&[]; 3]).is_err());
        }
        assert!(bounds(54).is_err());
    }
    #[test]
    fn unload_projection_requires_request_identity_and_only_optional_beneficiary() {
        let id = [7; 32];
        assert_eq!(bounds(45).unwrap(), [16_384, 0, 0]);
        assert!(matches!(
            request(&id, 45, 0, 0, [&[]; 3]).unwrap(),
            Setup::UnloadClaim { request_id, beneficiary: None } if request_id == id
        ));
        assert!(matches!(
            request(&id, 45, 0, 0, [&[1, 2], &[], &[]]).unwrap(),
            Setup::UnloadClaim { request_id, beneficiary: Some(original) }
                if request_id == id && original == [1, 2]
        ));
        assert!(request(&id, 45, 0, 0, [&vec![1; 16_384], &[], &[]]).is_ok());
        assert!(request(&[0; 32], 45, 0, 0, [&[]; 3]).is_err());
        assert!(request(&id, 45, 1, 0, [&[]; 3]).is_err());
        assert!(request(&id, 45, 0, 1, [&[]; 3]).is_err());
        assert!(request(&id, 45, 0, 0, [&vec![1; 16_385], &[], &[]]).is_err());
        assert!(request(&id, 45, 0, 0, [&[], &[1], &[]]).is_err());
        assert!(request(&id, 45, 0, 0, [&[], &[], &[1]]).is_err());
        assert!(request(&id, 33, 0, 0, [&[]; 3]).is_err());
        assert!(matches!(
            request(&id, 33, 0, 0, [&[1], &[], &[]]).unwrap(),
            Setup::UnloadProofProgress { transaction, .. } if transaction == id
        ));
    }
    #[test]
    fn activation_intake_and_progress_are_closed_and_exact() {
        let zero = [0; 32];
        for selector in [35, 36, 37, 46] {
            let second: &[u8] = if selector == 36 { &[2] } else { &[] };
            assert!(request(&zero, selector, 0, 0, [&[1], second, &[]]).is_ok());
            assert!(request(&zero, selector, 0, 0, [&[], second, &[]]).is_err());
            assert!(request(&[1; 32], selector, 0, 0, [&[1], second, &[]]).is_err());
            assert!(request(&zero, selector, 1, 0, [&[1], second, &[]]).is_err());
            assert!(request(&zero, selector, 0, 1, [&[1], second, &[]]).is_err());
            assert!(request(&zero, selector, 0, 0, [&[1], second, &[3]]).is_err());
            assert!(request(&zero, selector, 0, 0, [&vec![0; 65_537], second, &[]]).is_err());
        }
        assert!(request(&zero, 36, 0, 0, [&[1], &[], &[]]).is_err());
        for selector in [35, 37, 46] {
            assert!(request(&zero, selector, 0, 0, [&[1], &[2], &[]]).is_err());
        }
        let progress = state::LedgerProgressV1 {
            height: u64::MAX,
            block_hash: [9; 32],
        };
        for (value, kind) in [
            (state::ActivationFinalityProgressV1::Confirmed(progress), 44),
            (state::ActivationFinalityProgressV1::Verifying(progress), 45),
            (state::ActivationFinalityProgressV1::Rejected(progress), 49),
        ] {
            let output = activation_progress(value);
            assert_eq!(
                (output.kind, output.sequence, output.detail, output.bytes),
                (kind, u128::from(u64::MAX), 0, vec![9; 32])
            );
        }
        let output = activation_progress(state::ActivationFinalityProgressV1::NotStarted);
        assert_eq!(
            (output.kind, output.sequence, output.detail, output.bytes),
            (46, 0, 0, vec![])
        );
    }
    #[test]
    fn ledger_and_fee_setup_enforce_bounds_identity_and_progress_shape() {
        let zero = [0; 32];
        let credit = [7; 32];
        assert!(request(&credit, 20, 0, 0, [&[]; 3]).is_ok());
        assert!(request(&zero, 20, 0, 0, [&[]; 3]).is_err());
        for selector in 21..=23 {
            assert!(request(&zero, selector, 0, 0, [&[1], &[], &[]]).is_ok());
            assert!(request(&credit, selector, 0, 0, [&[1], &[], &[]]).is_err());
            assert!(request(&zero, selector, 0, 0, [&[]; 3]).is_err());
        }
        assert_eq!(bounds(26).unwrap(), [21_024, 16_384, 0]);
        assert!(request(&zero, 26, 0, 0, [&[1], &[2], &[]]).is_ok());
        for originals in [[&[1][..], &[][..], &[][..]], [&[1][..], &[2][..], &[3][..]]] {
            assert!(request(&zero, 26, 0, 0, originals).is_err());
        }
        assert!(request(&zero, 26, 0, 0, [&[1], &vec![0; 16_385], &[]]).is_err());
        assert_eq!(bounds(21).unwrap()[0], 21_024);
        assert_eq!(bounds(23).unwrap()[0], 36 * 1024 * 1024);
        assert_eq!(bounds(25).unwrap(), [32 * 1024 * 1024, 1024, 0]);
        assert!(request(&credit, 25, 0, 0, [&[1], &[2], &[]]).is_ok());
        assert!(request(&zero, 25, 0, 0, [&[1], &[2], &[]]).is_err());
        assert!(request(&credit, 25, 0, 0, [&[1], &[], &[]]).is_err());
        assert!(request(&credit, 25, 0, 1, [&[1], &[2], &[]]).is_err());
        assert!(request(&zero, 24, 0, 0, [&[]; 3]).is_ok());
        let result = ledger_progress(Some(state::LedgerProgressV1 {
            height: u64::MAX,
            block_hash: [9; 32],
        }));
        assert_eq!(
            (result.kind, result.sequence, result.detail, result.bytes),
            (33, u128::from(u64::MAX), 0, vec![9; 32])
        );
        let absent = ledger_progress(None);
        assert_eq!(
            (absent.kind, absent.sequence, absent.detail, absent.bytes),
            (34, 0, 0, vec![])
        );
    }
    #[test]
    fn ledger_producer_requests_keep_original_bounds_and_unused_authority_exact() {
        let id = [7; 32];
        let zero = [0; 32];
        assert!(matches!(
            request(&id, 27, u128::MAX, 0, [&[]; 3]).unwrap(),
            Setup::LedgerLoad { id: actual, amount: u128::MAX } if actual == id
        ));
        assert!(request(&id, 27, 0, 0, [&[]; 3]).is_err());
        assert!(request(&zero, 27, 1, 0, [&[]; 3]).is_err());
        assert!(request(&id, 27, 1, 0, [&[1], &[], &[]]).is_err());
        assert_eq!(bounds(29).unwrap(), [65_536, 0, 0]);
        assert_eq!(bounds(30).unwrap(), [65_536, 0, 0]);
        for token in [1, 2, 3] {
            assert!(matches!(
                request(&zero, 29, 0, token, [&[1], &[], &[]]).unwrap(),
                Setup::LedgerInstruction { kind, .. } if kind == token
            ));
            assert!(request(&id, 29, 0, token, [&[1], &[], &[]]).is_err());
            assert!(request(&zero, 29, 1, token, [&[1], &[], &[]]).is_err());
            assert!(request(&zero, 29, 0, token, [&[]; 3]).is_err());
            assert!(request(&zero, 29, 0, token, [&[1], &[2], &[]]).is_err());
            assert!(request(&zero, 29, 0, token, [&[1], &[], &[3]]).is_err());
        }
        for token in [0, 4, u64::MAX] {
            assert!(request(&zero, 29, 0, token, [&[1], &[], &[]]).is_err());
        }
        for selector in [28, 31, 32] {
            assert!(bounds(selector).is_err());
            assert!(request(&zero, selector, 0, 0, [&[]; 3]).is_err());
            assert!(request(&zero, selector, 0, 0, [&[1], &[2], &[]]).is_err());
            assert!(request(&zero, selector, 0, 0, [&vec![1; 513], &[2], &[]]).is_err());
            assert!(request(&id, selector, 0, 0, [&[1], &[2], &[]]).is_err());
        }
        for selector in [30, 33] {
            assert!(request(&id, selector, 0, 0, [&[1], &[], &[]]).is_ok());
            assert!(request(&zero, selector, 0, 0, [&[1], &[], &[]]).is_err());
            assert!(request(&id, selector, 1, 0, [&[1], &[], &[]]).is_err());
            assert!(request(&id, selector, 0, 1, [&[1], &[], &[]]).is_err());
            assert!(request(&id, selector, 0, 0, [&[]; 3]).is_err());
            assert!(request(&id, selector, 0, 0, [&[1], &[2], &[]]).is_err());
            assert!(request(&id, selector, 0, 0, [&[1], &[], &[3]]).is_err());
        }
        assert!(request(&id, 34, 0, 0, [&[1], &[2], &[]]).is_ok());
        assert!(request(&id, 34, 0, 0, [&[1], &[], &[]]).is_err());
        assert!(request(&zero, 34, 0, 0, [&[1], &[2], &[]]).is_err());
        assert_eq!(bounds(34).unwrap(), [65_536, 36 * 1024 * 1024, 0]);
    }
    #[test]
    fn malformed_time_response_retires_only_its_owned_exchange_before_decoding() {
        let vectors: norito::json::Value = norito::json::from_str(include_str!(
            "../../../../fixtures/kagemusha/wallet_v1_vectors.json"
        ))
        .unwrap();
        let original = |name| {
            let row = vectors["objects"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["type"].as_str() == Some(name))
                .unwrap();
            hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap()
        };
        let anchor = original("KagemushaWalletTimeAnchorV1");
        let certificate = original("KagemushaWalletSignerCertificateV1");
        let malformed = vec![7];
        let mut times = BTreeMap::from([(1, [11; 32]), (2, [22; 32]), (3, [33; 32])]);
        for (token, first, second) in [(1, &malformed, &certificate), (2, &anchor, &malformed)] {
            let Setup::FinishTime {
                token,
                anchor,
                certificate,
            } = request(&[0; 32], 5, 0, token, [first, second, &[]]).unwrap()
            else {
                panic!("bounded time originals must reach their native owner");
            };
            assert_eq!(
                take_time_response(&mut times, token, &anchor, &certificate)
                    .unwrap_err()
                    .status,
                INVALID,
            );
            assert!(!times.contains_key(&token));
            assert_eq!(times.get(&3), Some(&[33; 32]));
        }
        assert_eq!(times.len(), 1);
        assert_eq!(
            take_time_response(&mut times, 1, &anchor, &certificate)
                .unwrap_err()
                .status,
            INVALID,
        );
        let (exchange, decoded_anchor, decoded_certificate) =
            take_time_response(&mut times, 3, &anchor, &certificate).unwrap();
        assert_eq!(exchange, [33; 32]);
        assert_eq!(norito::encode_canonical(&decoded_anchor).unwrap(), anchor);
        assert_eq!(
            norito::encode_canonical(&decoded_certificate).unwrap(),
            certificate,
        );
        assert!(times.is_empty());
    }

    #[test]
    fn cancelling_time_discards_exact_token_once_without_replacing_other_exchanges() {
        let mut times = BTreeMap::from([(1, [11; 32]), (2, [22; 32])]);
        assert_eq!(take_time(&mut times, 1).unwrap(), [11; 32]);
        assert_eq!(take_time(&mut times, 1).unwrap_err().status, INVALID);
        assert_eq!(times.len(), 1);
        assert_eq!(take_time(&mut times, 2).unwrap(), [22; 32]);
        assert!(times.is_empty());
    }
}
