#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::routing::QueryOptions")]
#[derive(
    Debug, Default, Clone, crate::json_macros::JsonDeserialize, norito::derive::NoritoDeserialize,
)]
/// Optional query-string overrides for `/v1/query` endpoint.
pub struct QueryOptions {
    /// Override cursor mode: "ephemeral" or "stored".
    pub cursor_mode: Option<String>,
    /// Count mode: "bounded" avoids full count scans; "exact" preserves exact remaining counts.
    pub count_mode: Option<String>,
    /// Gas units provided for stored cursor mode (integer). When config minimum > 0,
    /// stored cursors require at least this many units.
    pub gas_units: Option<u64>,
}
/// Verify a signed query and return the authenticated request payload.
#[derive(Debug)]
pub struct SignedQueryAdmission {
    network_id: NetworkId,
    max_clock_skew: Duration,
    max_time_to_live: Duration,
    body_read_timeout: Duration,
    replay_cache: ReplayCache,
}
/// Invalid relationship between signed-query freshness and replay retention.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "signed-query replay retention must exceed twice the maximum clock skew and leave a nonzero request TTL"
)]
pub struct SignedQueryAdmissionConfigError;
impl SignedQueryAdmission {
    /// Construct exact-lineage signed-query admission with bounded one-shot replay protection.
    ///
    /// The maximum accepted request TTL is derived rather than configured independently:
    /// `replay_retention - 2 * max_clock_skew`. This guarantees every consumed nonce remains
    /// protected throughout the complete interval in which its signed request can be accepted.
    pub fn new(
        network_id: NetworkId,
        max_clock_skew: Duration,
        replay_retention: Duration,
        replay_capacity: NonZeroUsize,
    ) -> core::result::Result<Self, SignedQueryAdmissionConfigError> {
        let complete_skew_window = max_clock_skew
            .checked_mul(2)
            .ok_or(SignedQueryAdmissionConfigError)?;
        let max_time_to_live = replay_retention
            .checked_sub(complete_skew_window)
            .filter(|ttl| !ttl.is_zero())
            .ok_or(SignedQueryAdmissionConfigError)?;
        // A request created at the furthest accepted future skew can remain
        // valid for this complete interval. Using the same configured window
        // for body polling preserves every admissible signed request while
        // preventing a slow client from retaining an ingress slot forever.
        let body_read_timeout = max_time_to_live
            .checked_add(max_clock_skew)
            .ok_or(SignedQueryAdmissionConfigError)?;
        Ok(Self {
            network_id,
            max_clock_skew,
            max_time_to_live,
            body_read_timeout,
            replay_cache: ReplayCache::new(replay_retention, replay_capacity),
        })
    }
    /// Return the exact genesis-lineage identity accepted by this boundary.
    #[must_use]
    pub const fn network_id(&self) -> NetworkId {
        self.network_id
    }
    /// Return the largest signature-bound query lifetime accepted by this boundary.
    #[must_use]
    pub const fn max_time_to_live(&self) -> Duration {
        self.max_time_to_live
    }
    /// Return the complete configured interval in which body polling can
    /// still produce an admissible signed query.
    #[must_use]
    pub const fn body_read_timeout(&self) -> Duration {
        self.body_read_timeout
    }
}
fn signed_query_now_unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            Error::from(ValidationFail::NotPermitted(
                "node clock precedes Unix epoch".to_owned(),
            ))
        })?
        .as_millis()
        .try_into()
        .map_err(|_| {
            Error::from(ValidationFail::NotPermitted(
                "node clock exceeds signed-query timestamp range".to_owned(),
            ))
        })
}
fn validate_signed_query_context_at(
    payload: &QueryRequestWithAuthority,
    admission: &SignedQueryAdmission,
    now_ms: u64,
) -> Result<()> {
    if payload.network_id != admission.network_id {
        return Err(Error::from(ValidationFail::NotPermitted(
            "signed query targets a different network genesis".to_owned(),
        )));
    }
    let max_clock_skew_ms = u64::try_from(admission.max_clock_skew.as_millis()).unwrap_or(u64::MAX);
    if payload.creation_time_ms > now_ms.saturating_add(max_clock_skew_ms) {
        return Err(Error::from(ValidationFail::NotPermitted(
            "signed query creation time exceeds the allowed future clock skew".to_owned(),
        )));
    }
    let request_ttl = Duration::from_millis(payload.time_to_live_ms.get());
    if request_ttl > admission.max_time_to_live {
        return Err(Error::from(ValidationFail::NotPermitted(format!(
            "signed query time-to-live {} ms exceeds the replay-retention bound {} ms",
            payload.time_to_live_ms,
            admission.max_time_to_live.as_millis()
        ))));
    }
    let expires_at_ms = payload
        .creation_time_ms
        .checked_add(payload.time_to_live_ms.get())
        .ok_or_else(|| {
            Error::from(ValidationFail::NotPermitted(
                "signed query creation time plus time-to-live overflows".to_owned(),
            ))
        })?;
    if now_ms >= expires_at_ms {
        return Err(Error::from(ValidationFail::QueryFailed(
            QueryExecutionFail::Expired,
        )));
    }
    if payload.nonce == [0_u8; 32] {
        return Err(Error::from(ValidationFail::NotPermitted(
            "signed query nonce must not be all-zero".to_owned(),
        )));
    }
    Ok(())
}
fn consume_signed_query_nonce(
    payload: &QueryRequestWithAuthority,
    admission: &SignedQueryAdmission,
) -> Result<()> {
    consume_signed_query_replay_key(payload, None, admission)
}
/// Consume one authenticated internal route-scan replay key.
///
/// A fanout coordinator consumes the client nonce once. Its sequential route
/// scans then use this route-qualified key so a validator that owns multiple
/// dataspaces can execute each authorized route exactly once without treating
/// the second route as a replay of the first.
pub fn consume_signed_query_route_scan_nonce(
    payload: &QueryRequestWithAuthority,
    route: RoutingDecision,
    admission: &SignedQueryAdmission,
) -> Result<()> {
    consume_signed_query_replay_key(payload, Some(route), admission)
}
fn consume_signed_query_replay_key(
    payload: &QueryRequestWithAuthority,
    route: Option<RoutingDecision>,
    admission: &SignedQueryAdmission,
) -> Result<()> {
    const CLIENT_DOMAIN: &[u8] = b"iroha:torii:signed-query-client-replay:v1\0";
    const ROUTE_DOMAIN: &[u8] = b"iroha:torii:signed-query-route-replay:v1\0";
    let replay_key = Hash::new_from_writer(|writer| {
        std::io::Write::write_all(
            writer,
            if route.is_some() {
                ROUTE_DOMAIN
            } else {
                CLIENT_DOMAIN
            },
        )?;
        std::io::Write::write_all(writer, payload.network_id.as_bytes())?;
        std::io::Write::write_all(writer, &payload.nonce)?;
        let public_key = payload
            .authority
            .controller()
            .single_signatory()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "signed-query authority is not single-key",
                )
            })?;
        let (algorithm, key_payload) = public_key.try_to_bytes().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "signed-query public key is malformed",
            )
        })?;
        let algorithm = algorithm.as_static_str().as_bytes();
        let algorithm_len = u16::try_from(algorithm.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "signed-query algorithm name exceeds replay-key framing",
            )
        })?;
        let key_len = u32::try_from(key_payload.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "signed-query public key exceeds replay-key framing",
            )
        })?;
        std::io::Write::write_all(writer, &algorithm_len.to_be_bytes())?;
        std::io::Write::write_all(writer, algorithm)?;
        std::io::Write::write_all(writer, &key_len.to_be_bytes())?;
        std::io::Write::write_all(writer, key_payload)?;
        if let Some(route) = route {
            std::io::Write::write_all(writer, &route.lane_id.as_u32().to_be_bytes())?;
            std::io::Write::write_all(writer, &route.dataspace_id.as_u64().to_be_bytes())?;
        }
        Ok(())
    })
    .map_err(|_| {
        Error::from(ValidationFail::QueryFailed(
            QueryExecutionFail::CapacityLimit,
        ))
    })?;
    match admission.replay_cache.check_and_insert_digest(replay_key) {
        Ok(()) => Ok(()),
        Err(ReplayInsertError::Replay) => Err(Error::from(ValidationFail::NotPermitted(
            "signed query nonce already used".to_owned(),
        ))),
        Err(ReplayInsertError::Capacity | ReplayInsertError::LifetimeOverflow) => Err(Error::from(
            ValidationFail::QueryFailed(QueryExecutionFail::CapacityLimit),
        )),
    }
}
/// Verify and consume one exact-lineage, fresh signed query request.
///
/// Network and time bounds are checked before signature work. The nonce is consumed only after a
/// valid single-key signature, and before account authorization or query execution.
pub fn verify_signed_query_request(
    query: SignedQuery,
    admission: &SignedQueryAdmission,
) -> Result<iroha_data_model::query::QueryRequestWithAuthority> {
    let now_ms = signed_query_now_unix_ms()?;
    verify_signed_query_request_at(query, admission, now_ms)
}
/// Authenticate a fresh internal fanout route scan without consuming the
/// client-wide nonce a second time.
///
/// Callers must validate the exact authorized route and then invoke
/// [`consume_signed_query_route_scan_nonce`] before query execution. Keeping
/// those operations separate avoids consuming cache capacity for an invalid
/// route hint while retaining exact-route replay protection.
pub fn authenticate_signed_query_route_scan_request(
    query: SignedQuery,
    admission: &SignedQueryAdmission,
) -> Result<iroha_data_model::query::QueryRequestWithAuthority> {
    let now_ms = signed_query_now_unix_ms()?;
    authenticate_signed_query_request_at(query, admission, now_ms)
}
fn verify_signed_query_request_at(
    query: SignedQuery,
    admission: &SignedQueryAdmission,
    now_ms: u64,
) -> Result<iroha_data_model::query::QueryRequestWithAuthority> {
    let payload = authenticate_signed_query_request_at(query, admission, now_ms)?;
    consume_signed_query_nonce(&payload, admission)?;
    Ok(payload)
}
fn authenticate_signed_query_request_at(
    query: SignedQuery,
    admission: &SignedQueryAdmission,
    now_ms: u64,
) -> Result<iroha_data_model::query::QueryRequestWithAuthority> {
    validate_signed_query_context_at(&query.payload, admission, now_ms)?;
    query.verify_signature().map_err(|error| {
        if matches!(error, SignedQueryValidationError::DecodeResourceLimit) {
            return Error::from(ValidationFail::QueryFailed(
                QueryExecutionFail::CapacityLimit,
            ));
        }
        let reason = match error {
            SignedQueryValidationError::AuthorityNotSingleKey => {
                "signed query authority must use a single-key controller".to_owned()
            }
            SignedQueryValidationError::InvalidSignatureMaterial => {
                "query signature material failed admission".to_owned()
            }
            SignedQueryValidationError::InvalidSignature => {
                "query signature failed verification".to_owned()
            }
            SignedQueryValidationError::InvalidRequest(reason) => {
                format!("signed query request is invalid: {reason}")
            }
            SignedQueryValidationError::DecodeResourceLimit => unreachable!(
                "decode resource failure returned before validation diagnostic construction"
            ),
        };
        Error::from(ValidationFail::NotPermitted(reason))
    })?;
    Ok(query.payload)
}
#[cfg(test)]
mod signed_query_verification_tests {
    use super::*;
    use iroha_crypto::SignatureOf;
    use iroha_data_model::{
        account::{AccountId, MultisigMember, MultisigPolicy},
        block::BlockHeader,
        query::{
            QueryRequest, QuerySignature, SingularQueryBox,
            executor::prelude::FindExecutorDataModel, runtime::prelude::FindAbiVersion,
        },
    };
    const NOW_MS: u64 = 1_000_000;
    fn network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([seed; Hash::LENGTH]),
        ))
    }
    fn admission_for(network_id: NetworkId) -> SignedQueryAdmission {
        admission_with_capacity(network_id, NonZeroUsize::new(16).expect("nonzero capacity"))
    }
    fn admission_with_capacity(
        network_id: NetworkId,
        replay_capacity: NonZeroUsize,
    ) -> SignedQueryAdmission {
        SignedQueryAdmission::new(
            network_id,
            Duration::from_secs(1),
            Duration::from_secs(12),
            replay_capacity,
        )
        .expect("valid signed-query admission fixture")
    }
    fn signed_find_abi_version(
        key_pair: &KeyPair,
        network_id: NetworkId,
        creation_time_ms: u64,
        time_to_live_ms: u64,
        nonce_seed: u8,
    ) -> SignedQuery {
        let authority = AccountId::new(key_pair.public_key().clone());
        QueryRequest::Singular(SingularQueryBox::FindAbiVersion(FindAbiVersion))
            .with_authority(
                network_id,
                authority,
                creation_time_ms,
                NonZeroU64::new(time_to_live_ms).expect("nonzero query TTL fixture"),
                [nonce_seed; 32],
            )
            .sign(key_pair)
    }
    fn fresh_signed_find_abi_version(
        key_pair: &KeyPair,
        network_id: NetworkId,
        nonce_seed: u8,
    ) -> SignedQuery {
        signed_find_abi_version(key_pair, network_id, NOW_MS, 10_000, nonce_seed)
    }
    const SMALL_ORDER_ED25519_SIGNATURE_R: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    const NONCANONICAL_ED25519_SIGNATURE_R: [u8; 32] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    fn signature_of_with_malformed_ed25519_r<T>(
        signature: &SignatureOf<T>,
        replacement_r: &[u8; 32],
    ) -> SignatureOf<T> {
        let mut payload = signature.payload().to_vec();
        payload[..replacement_r.len()].copy_from_slice(replacement_r);
        SignatureOf::from_signature(Signature::from_bytes(&payload))
    }
    #[test]
    fn body_read_timeout_covers_future_skew_and_complete_ttl() {
        let admission = SignedQueryAdmission::new(
            network_id(0x30),
            Duration::from_secs(2),
            Duration::from_secs(12),
            NonZeroUsize::new(1).expect("nonzero replay capacity"),
        )
        .expect("valid signed-query admission window");
        assert_eq!(admission.max_time_to_live(), Duration::from_secs(8));
        assert_eq!(admission.body_read_timeout(), Duration::from_secs(10));
    }
    #[test]
    fn verified_signed_query_returns_authenticated_payload() {
        let key_pair = checked_routing_fixture_keypair(
            0xe3,
            Algorithm::Ed25519,
            "derive signed query fixture key",
        );
        let authority = AccountId::new(key_pair.public_key().clone());
        let network_id = network_id(0x31);
        let admission = admission_for(network_id);
        let signed = fresh_signed_find_abi_version(&key_pair, network_id, 1);
        let verified = verify_signed_query_request_at(signed, &admission, NOW_MS)
            .expect("signed query should verify");
        let (verified_authority, verified_request) = verified.into_parts();
        assert_eq!(verified_authority, authority);
        assert!(matches!(
            verified_request,
            QueryRequest::Singular(SingularQueryBox::FindAbiVersion(_))
        ));
    }
    #[test]
    fn verify_signed_query_rejects_mismatched_authority() {
        let signer = checked_routing_fixture_keypair(
            0xe4,
            Algorithm::Ed25519,
            "derive signed query signer fixture key",
        );
        let other = checked_routing_fixture_keypair(
            0xe5,
            Algorithm::Ed25519,
            "derive signed query other authority fixture key",
        );
        let network_id = network_id(0x32);
        let admission = admission_for(network_id);
        let mut signed_payload = fresh_signed_find_abi_version(&signer, network_id, 2);
        signed_payload.payload.authority = AccountId::new(other.public_key().clone());
        assert!(verify_signed_query_request_at(signed_payload, &admission, NOW_MS).is_err());
    }
    #[test]
    fn verify_signed_query_rejects_multisig_authority_without_panicking() {
        let signer = checked_routing_fixture_keypair(
            0xe8,
            Algorithm::Ed25519,
            "derive signed query multisig fixture key",
        );
        let member =
            MultisigMember::new(signer.public_key().clone(), 1).expect("valid multisig member");
        let policy = MultisigPolicy::new(1, vec![member]).expect("valid multisig policy");
        let network_id = network_id(0x33);
        let admission = admission_for(network_id);
        let mut malformed = fresh_signed_find_abi_version(&signer, network_id, 3);
        malformed.payload.authority = AccountId::new_multisig(policy);
        let response = match verify_signed_query_request_at(malformed, &admission, NOW_MS) {
            Ok(_) => panic!("directly signed multisig query authority must be rejected"),
            Err(error) => error.into_response(),
        };
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        verify_signed_query_request_at(
            fresh_signed_find_abi_version(&signer, network_id, 3),
            &admission,
            NOW_MS,
        )
        .expect("a valid follow-up query must still verify");
    }
    #[test]
    fn verify_signed_query_rejects_malformed_ed25519_signature_r() {
        let signer = checked_routing_fixture_keypair(
            0xe6,
            Algorithm::Ed25519,
            "derive signed query malformed signature fixture key",
        );
        let network_id = network_id(0x34);
        let admission = admission_for(network_id);
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_ED25519_SIGNATURE_R),
            ("noncanonical", NONCANONICAL_ED25519_SIGNATURE_R),
        ] {
            let mut invalid_signed = fresh_signed_find_abi_version(&signer, network_id, 4);
            invalid_signed.signature = QuerySignature(signature_of_with_malformed_ed25519_r(
                &invalid_signed.signature.0,
                &replacement_r,
            ));
            let err = match verify_signed_query_request_at(invalid_signed, &admission, NOW_MS) {
                Ok(_) => panic!("malformed signed query signature R must fail admission"),
                Err(err) => err,
            };
            let message = format!("{err:?}");
            assert!(
                message.contains("query signature material failed admission"),
                "{label} signed query signature R produced unexpected admission error: {message}"
            );
        }
    }
    #[test]
    fn verify_signed_query_rejects_malformed_mldsa_signature_lengths() {
        let signer = checked_routing_fixture_keypair(
            0xe7,
            Algorithm::MlDsa,
            "derive signed query malformed ML-DSA signature fixture key",
        );
        let network_id = network_id(0x35);
        let admission = admission_for(network_id);
        verify_signed_query_request_at(
            fresh_signed_find_abi_version(&signer, network_id, 5),
            &admission,
            NOW_MS,
        )
        .expect("valid ML-DSA signed query should verify before mutation");
        for label in ["truncated", "extended"] {
            let mut invalid_signed = fresh_signed_find_abi_version(&signer, network_id, 6);
            let mut malformed_payload = invalid_signed.signature.0.payload().to_vec();
            match label {
                "truncated" => {
                    malformed_payload.pop();
                }
                "extended" => malformed_payload.push(0),
                _ => unreachable!("test labels are exhaustive"),
            }
            invalid_signed.signature = QuerySignature(SignatureOf::from_signature(
                Signature::from_bytes(&malformed_payload),
            ));
            let err = match verify_signed_query_request_at(invalid_signed, &admission, NOW_MS) {
                Ok(_) => {
                    panic!("malformed signed query ML-DSA signature length must fail admission")
                }
                Err(err) => err,
            };
            let message = format!("{err:?}");
            assert!(
                message.contains("query signature material failed admission"),
                "{label} signed query ML-DSA signature length produced unexpected admission error: {message}"
            );
        }
    }
    #[test]
    fn signed_query_cannot_cross_genesis_lineages() {
        let signer = checked_routing_fixture_keypair(
            0xe9,
            Algorithm::Ed25519,
            "derive cross-network signed-query fixture key",
        );
        let source_network = network_id(0x41);
        let other_network = network_id(0x42);
        let error = match verify_signed_query_request_at(
            fresh_signed_find_abi_version(&signer, source_network, 7),
            &admission_for(other_network),
            NOW_MS,
        ) {
            Ok(_) => panic!("a signed query must not cross genesis lineages"),
            Err(error) => error,
        };
        assert!(format!("{error:?}").contains("different network genesis"));
        verify_signed_query_request_at(
            fresh_signed_find_abi_version(&signer, source_network, 7),
            &admission_for(source_network),
            NOW_MS,
        )
        .expect("wrong-network rejection must not invalidate the original request");
    }
    #[test]
    fn signed_query_rejects_expired_and_excessively_future_timestamps() {
        let signer = checked_routing_fixture_keypair(
            0xea,
            Algorithm::Ed25519,
            "derive signed-query freshness fixture key",
        );
        let network_id = network_id(0x43);
        let admission = admission_for(network_id);
        let expired = signed_find_abi_version(&signer, network_id, NOW_MS - 10_000, 10_000, 8);
        let error = match verify_signed_query_request_at(expired, &admission, NOW_MS) {
            Ok(_) => panic!("expiry is exclusive at creation time plus TTL"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            Error::Query(ValidationFail::QueryFailed(QueryExecutionFail::Expired))
        ));
        let future = signed_find_abi_version(&signer, network_id, NOW_MS + 1_001, 10_000, 9);
        let error = match verify_signed_query_request_at(future, &admission, NOW_MS) {
            Ok(_) => panic!("creation time beyond clock skew must fail"),
            Err(error) => error,
        };
        assert!(format!("{error:?}").contains("future clock skew"));
    }
    #[test]
    fn signed_query_rejects_zero_nonce_and_ttl_beyond_replay_retention() {
        let signer = checked_routing_fixture_keypair(
            0xee,
            Algorithm::Ed25519,
            "derive signed-query context-bound fixture key",
        );
        let network_id = network_id(0x49);
        let admission = admission_for(network_id);
        let zero_nonce = signed_find_abi_version(&signer, network_id, NOW_MS, 10_000, 0);
        let error = match verify_signed_query_request_at(zero_nonce, &admission, NOW_MS) {
            Ok(_) => panic!("the all-zero nonce sentinel must fail closed"),
            Err(error) => error,
        };
        assert!(format!("{error:?}").contains("nonce must not be all-zero"));
        let excessive_ttl = signed_find_abi_version(&signer, network_id, NOW_MS, 10_001, 14);
        let error = match verify_signed_query_request_at(excessive_ttl, &admission, NOW_MS) {
            Ok(_) => panic!("request lifetime must fit entirely inside replay retention"),
            Err(error) => error,
        };
        assert!(format!("{error:?}").contains("replay-retention bound"));
    }
    #[test]
    fn every_signed_context_field_is_integrity_protected() {
        let signer = checked_routing_fixture_keypair(
            0xeb,
            Algorithm::Ed25519,
            "derive signed-query tamper fixture key",
        );
        let source_network = network_id(0x44);
        let admission = admission_for(source_network);
        let mut mutations = Vec::new();
        let mut changed_network = fresh_signed_find_abi_version(&signer, source_network, 10);
        changed_network.payload.network_id = network_id(0x45);
        mutations.push(("network_id", changed_network));
        let mut changed_creation_time = fresh_signed_find_abi_version(&signer, source_network, 10);
        changed_creation_time.payload.creation_time_ms += 1;
        mutations.push(("creation_time_ms", changed_creation_time));
        let mut changed_ttl = fresh_signed_find_abi_version(&signer, source_network, 10);
        changed_ttl.payload.time_to_live_ms = NonZeroU64::new(9_999).expect("nonzero TTL");
        mutations.push(("time_to_live_ms", changed_ttl));
        let mut changed_nonce = fresh_signed_find_abi_version(&signer, source_network, 10);
        changed_nonce.payload.nonce = [0x46; 32];
        mutations.push(("nonce", changed_nonce));
        let mut changed_request = fresh_signed_find_abi_version(&signer, source_network, 10);
        changed_request.payload.request = QueryRequest::Singular(
            SingularQueryBox::FindExecutorDataModel(FindExecutorDataModel),
        );
        mutations.push(("request", changed_request));
        for (field, mutation) in mutations {
            let _error = match verify_signed_query_request_at(mutation, &admission, NOW_MS) {
                Ok(_) => panic!("tampering with {field} must be rejected"),
                Err(error) => error,
            };
        }
        verify_signed_query_request_at(
            fresh_signed_find_abi_version(&signer, source_network, 10),
            &admission,
            NOW_MS,
        )
        .expect("tampered requests must not consume the authentic nonce");
    }
    #[test]
    fn signed_query_nonce_is_consumed_exactly_once() {
        let signer = checked_routing_fixture_keypair(
            0xec,
            Algorithm::Ed25519,
            "derive signed-query replay fixture key",
        );
        let network_id = network_id(0x47);
        let admission = admission_for(network_id);
        verify_signed_query_request_at(
            fresh_signed_find_abi_version(&signer, network_id, 11),
            &admission,
            NOW_MS,
        )
        .expect("first use must pass");
        let error = match verify_signed_query_request_at(
            fresh_signed_find_abi_version(&signer, network_id, 11),
            &admission,
            NOW_MS,
        ) {
            Ok(_) => panic!("second use of the same signed nonce must fail"),
            Err(error) => error,
        };
        assert!(format!("{error:?}").contains("nonce already used"));
    }
    #[test]
    fn fanout_route_replay_keys_are_exact_route_scoped() {
        let signer = checked_routing_fixture_keypair(
            0xe8,
            Algorithm::Ed25519,
            "derive signed-query fanout replay fixture key",
        );
        let network_id = network_id(0x4a);
        let admission = admission_for(network_id);
        let first_route = RoutingDecision::new(LaneId::new(3), DataSpaceId::new(9));
        let second_route = RoutingDecision::new(LaneId::new(3), DataSpaceId::new(10));
        let client = verify_signed_query_request_at(
            fresh_signed_find_abi_version(&signer, network_id, 12),
            &admission,
            NOW_MS,
        )
        .expect("the fanout coordinator consumes the client nonce once");
        consume_signed_query_route_scan_nonce(&client, first_route, &admission)
            .expect("the first authorized route has an independent replay key");
        let second = authenticate_signed_query_request_at(
            fresh_signed_find_abi_version(&signer, network_id, 12),
            &admission,
            NOW_MS,
        )
        .expect("an internal route scan re-authenticates the client signature");
        consume_signed_query_route_scan_nonce(&second, second_route, &admission)
            .expect("one validator may serve a second authorized dataspace");
        let replay = authenticate_signed_query_request_at(
            fresh_signed_find_abi_version(&signer, network_id, 12),
            &admission,
            NOW_MS,
        )
        .expect("the replay remains cryptographically authentic");
        let error = consume_signed_query_route_scan_nonce(&replay, first_route, &admission)
            .expect_err("the same internal route scan must remain one-shot");
        assert!(format!("{error:?}").contains("nonce already used"));
    }
    #[test]
    fn signed_query_replay_cache_saturation_fails_closed_without_eviction() {
        let signer = checked_routing_fixture_keypair(
            0xed,
            Algorithm::Ed25519,
            "derive signed-query capacity fixture key",
        );
        let network_id = network_id(0x48);
        let admission = admission_with_capacity(
            network_id,
            NonZeroUsize::new(1).expect("nonzero replay capacity"),
        );
        let second = fresh_signed_find_abi_version(&signer, network_id, 13);
        verify_signed_query_request_at(
            fresh_signed_find_abi_version(&signer, network_id, 12),
            &admission,
            NOW_MS,
        )
        .expect("first nonce must fit");
        let error = match verify_signed_query_request_at(second, &admission, NOW_MS) {
            Ok(_) => panic!("a full live replay cache must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            Error::Query(ValidationFail::QueryFailed(
                QueryExecutionFail::CapacityLimit
            ))
        ));
        let error = match verify_signed_query_request_at(
            fresh_signed_find_abi_version(&signer, network_id, 12),
            &admission,
            NOW_MS,
        ) {
            Ok(_) => panic!("capacity rejection must not evict the live replay record"),
            Err(error) => error,
        };
        assert!(format!("{error:?}").contains("nonce already used"));
    }
}
/// Immutable ordinary-query execution facts shared by admission and Core.
#[derive(Clone, Copy, Debug)]
pub struct OrdinaryQueryExecutionPlan {
    mode: iroha_core::query::snapshot::CursorMode,
    limits: iroha_core::smartcontracts::isi::query::QueryLimits,
    ordinary_limits: iroha_core::smartcontracts::isi::query::OrdinaryQueryExecutionLimits,
    singular_execution: bool,
    stored_start_budget: Option<u64>,
    requested_gas_budget: Option<u64>,
    continue_budget: Option<u64>,
}
impl OrdinaryQueryExecutionPlan {
    pub(crate) fn is_stored_start(self, request: &iroha_data_model::query::QueryRequest) -> bool {
        self.mode == iroha_core::query::snapshot::CursorMode::Stored
            && matches!(request, iroha_data_model::query::QueryRequest::Start(_))
    }
    /// Whether this request needs the complete source-bounded singular lane.
    pub(crate) const fn requires_singular_execution(self) -> bool {
        self.singular_execution
    }
}
/// Capture one app-local ordinary policy before any weighted promotion.
pub fn ordinary_query_execution_plan(
    state: &CoreState,
    request: &iroha_data_model::query::QueryRequest,
    opts: &QueryOptions,
    policy: crate::OrdinaryQueryServerPolicy,
) -> Result<OrdinaryQueryExecutionPlan> {
    use iroha_core::{
        query::snapshot::CursorMode,
        smartcontracts::isi::query::{QueryCountMode, QueryLimits},
    };
    let pipeline = state.pipeline_snapshot();
    let configured_mode = || match pipeline.query_default_cursor_mode {
        iroha_config::parameters::actual::QueryCursorMode::Ephemeral => CursorMode::Ephemeral,
        iroha_config::parameters::actual::QueryCursorMode::Stored => CursorMode::Stored,
    };
    let mode = match opts.cursor_mode.as_deref() {
        Some("ephemeral") => CursorMode::Ephemeral,
        Some("stored") => CursorMode::Stored,
        Some(other) => {
            iroha_logger::warn!(
                other,
                "unknown cursor_mode override; falling back to config"
            );
            configured_mode()
        }
        None => configured_mode(),
    };
    let continue_budget = match request {
        iroha_data_model::query::QueryRequest::Continue(cursor) => cursor.gas_budget,
        _ => None,
    };
    let stored_start_budget = match request {
        iroha_data_model::query::QueryRequest::Start(_) => opts.gas_units,
        _ => None,
    };
    let min_gas = pipeline.query_stored_min_gas_units;
    if min_gas > 0 && mode == CursorMode::Stored {
        let provided = continue_budget.or(opts.gas_units).unwrap_or(0);
        if provided < min_gas {
            return Err(ValidationFail::NotPermitted(format!(
                "stored cursor requires at least {min_gas} gas units"
            ))
            .into());
        }
    }
    let count_mode = match opts.count_mode.as_deref() {
        Some("exact") => QueryCountMode::Exact,
        Some("bounded") | None => QueryCountMode::Bounded,
        Some(other) => {
            iroha_logger::warn!(other, "unknown count_mode override; using bounded");
            QueryCountMode::Bounded
        }
    };
    let singular_execution = matches!(
        request,
        iroha_data_model::query::QueryRequest::Singular(query)
            if !matches!(
                query,
                iroha_data_model::query::SingularQueryBox::FindAbiVersion(_)
            )
    );
    let mut limits = QueryLimits::new(policy.max_fetch_size).with_count_mode(count_mode);
    if singular_execution {
        limits = limits.with_singular_output_limits(policy.singular_output_limits);
    }
    Ok(OrdinaryQueryExecutionPlan {
        mode,
        limits,
        ordinary_limits: policy.limits,
        singular_execution,
        stored_start_budget,
        requested_gas_budget: opts.gas_units,
        continue_budget,
    })
}
/// Execute an ordinary query while Core owns the server's weighted lease.
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub async fn execute_admitted_verified_query_with_server_owned_memory(
    live_query_store: LiveQueryStoreHandle,
    state: Arc<CoreState>,
    query: iroha_data_model::query::QueryRequestWithAuthority,
    tel: MaybeTelemetry,
    plan: &OrdinaryQueryExecutionPlan,
    admission: crate::QueryAdmissionPermit,
    memory_lease: iroha_core::smartcontracts::isi::query::OrdinaryQueryMemoryLease,
) -> Result<iroha_core::query::snapshot::ServerOwnedQueryResponse> {
    use iroha_core::query::snapshot::{
        CursorMode, SnapshotQueryError, run_on_snapshot_with_server_owned_memory_arc,
    };
    #[cfg(feature = "telemetry")]
    let start = std::time::Instant::now();
    let authority = query.authority;
    let request = query.request;
    let is_iterable = matches!(
        &request,
        iroha_data_model::query::QueryRequest::Start(_)
            | iroha_data_model::query::QueryRequest::Continue(_)
    );
    let &OrdinaryQueryExecutionPlan {
        mode,
        limits,
        stored_start_budget,
        ordinary_limits,
        ..
    } = plan;
    let state_cloned = Arc::clone(&state);
    let store_cloned = live_query_store.clone();
    let response = crate::panic_recovery::join_recoverable(
        crate::panic_recovery::spawn_blocking_recoverable(move || {
            // Cancellation detaches blocking work. Both permits therefore belong
            // to the worker until validation and execution have actually ended.
            let _admission = admission;
            run_on_snapshot_with_server_owned_memory_arc(
                &state_cloned,
                &store_cloned,
                &authority,
                request,
                mode,
                limits,
                stored_start_budget,
                ordinary_limits,
                memory_lease,
            )
        }),
    )
    .await
    .map_err(|error| ValidationFail::InternalError(format!("query worker join error: {error}")))
    .and_then(|result| {
        result.map_err(|error| match error {
            SnapshotQueryError::Validation(validation) => validation,
            SnapshotQueryError::Execution(execution) => ValidationFail::QueryFailed(execution),
        })
    })?;
    #[cfg(feature = "telemetry")]
    if tel.is_enabled() {
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        let mode_label = match plan.mode {
            CursorMode::Ephemeral => "ephemeral",
            CursorMode::Stored => "stored",
        };
        let mut gas_units = [0_u64; 2];
        let mut gas_count = 0_usize;
        if plan.mode == CursorMode::Stored {
            if let Some(units) = plan.requested_gas_budget {
                gas_units[gas_count] = units;
                gas_count += 1;
            }
            if let Some(units) = plan.continue_budget {
                gas_units[gas_count] = units;
                gas_count += 1;
            }
        }
        let _ = tel.with_metrics(|telemetry| {
            telemetry.observe_torii_query_snapshot(
                mode_label,
                is_iterable.then_some(elapsed_ms),
                &gas_units[..gas_count],
            );
        });
    }
    Ok(response)
}
/// Execute a previously verified query request with the provided options.
#[cfg(any(test, feature = "test-fixtures", feature = "bench"))]
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub async fn execute_verified_query_with_opts(
    live_query_store: LiveQueryStoreHandle,
    state: Arc<CoreState>,
    query: iroha_data_model::query::QueryRequestWithAuthority,
    tel: MaybeTelemetry,
    opts: QueryOptions,
) -> Result<iroha_data_model::query::QueryResponse> {
    execute_verified_query_with_opts_inner(live_query_store, state, query, tel, opts, None, None)
        .await
}
/// Output-specific Core limits carried by one server-owned fanout execution.
#[derive(Clone, Copy, Debug)]
pub enum FanoutQueryOutputLimits {
    /// Bounded producer/ownership limits for an admitted singular query.
    Singular(iroha_core::smartcontracts::isi::query::SingularQueryOutputLimits),
}
/// Execute an admitted verified query in the server-owned bounded fanout lane.
///
/// This entry point always uses ephemeral cursor semantics and carries both the
/// deterministic scan-work budget and output-specific memory limits into Core
/// before any query result is projected or materialized.
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub async fn execute_admitted_verified_query_for_fanout(
    live_query_store: LiveQueryStoreHandle,
    state: Arc<CoreState>,
    query: iroha_data_model::query::QueryRequestWithAuthority,
    tel: MaybeTelemetry,
    output_limits: FanoutQueryOutputLimits,
    execution_budget: iroha_core::smartcontracts::isi::query::QueryExecutionBudget,
    (admission, fanout_reservation): (
        crate::QueryAdmissionPermit,
        crate::QueryFanoutMemoryReservation,
    ),
) -> Result<iroha_data_model::query::QueryResponse> {
    execute_verified_query_with_opts_inner(
        live_query_store,
        state,
        query,
        tel,
        QueryOptions::default(),
        Some(admission),
        Some((output_limits, execution_budget, fanout_reservation)),
    )
    .await
}
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
async fn execute_verified_query_with_opts_inner(
    live_query_store: LiveQueryStoreHandle,
    state: Arc<CoreState>,
    query: iroha_data_model::query::QueryRequestWithAuthority,
    tel: MaybeTelemetry,
    opts: QueryOptions,
    admission: Option<crate::QueryAdmissionPermit>,
    fanout_execution: Option<(
        FanoutQueryOutputLimits,
        iroha_core::smartcontracts::isi::query::QueryExecutionBudget,
        crate::QueryFanoutMemoryReservation,
    )>,
) -> Result<iroha_data_model::query::QueryResponse> {
    use iroha_core::{
        query::snapshot::{
            CursorMode as LaneCursorMode, SnapshotQueryError,
            run_on_snapshot_ephemeral_with_budget_arc,
            run_on_snapshot_with_mode_arc_and_start_budget,
        },
        smartcontracts::isi::query::{QueryCountMode, QueryLimits},
    };
    #[cfg(feature = "telemetry")]
    let start = std::time::Instant::now();
    let authority = query.authority.clone();
    let request = query.request;
    let pipeline = state.pipeline_snapshot();
    // Map config cursor mode to lane cursor mode (with query override)
    let mode = if fanout_execution.is_some() {
        LaneCursorMode::Ephemeral
    } else {
        match opts.cursor_mode.as_deref() {
            Some("ephemeral") => LaneCursorMode::Ephemeral,
            Some("stored") => LaneCursorMode::Stored,
            Some(other) => {
                iroha_logger::warn!(
                    other,
                    "unknown cursor_mode override; falling back to config"
                );
                match pipeline.query_default_cursor_mode {
                    iroha_config::parameters::actual::QueryCursorMode::Ephemeral => {
                        LaneCursorMode::Ephemeral
                    }
                    iroha_config::parameters::actual::QueryCursorMode::Stored => {
                        LaneCursorMode::Stored
                    }
                }
            }
            None => match pipeline.query_default_cursor_mode {
                iroha_config::parameters::actual::QueryCursorMode::Ephemeral => {
                    LaneCursorMode::Ephemeral
                }
                iroha_config::parameters::actual::QueryCursorMode::Stored => LaneCursorMode::Stored,
            },
        }
    };
    #[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
    let mode_label = match mode {
        LaneCursorMode::Ephemeral => "ephemeral",
        LaneCursorMode::Stored => "stored",
    };
    // Optional gas gating for stored cursor mode (resource bound).
    // If configured (> 0) and the effective mode is Stored, enforce a minimum
    // client-provided budget. For continuations, honor the cursor's gas budget.
    // Budget-aware stored queries also enforce this allowance against projection
    // work; other query types use it as the server-side cursor admission guard.
    {
        let min_gas = pipeline.query_stored_min_gas_units;
        if min_gas > 0 && matches!(mode, LaneCursorMode::Stored) {
            let provided = match &request {
                iroha_data_model::query::QueryRequest::Continue(cursor) => {
                    cursor.gas_budget.unwrap_or(0)
                }
                _ => opts.gas_units.unwrap_or(0),
            };
            if provided < min_gas {
                return Err(ValidationFail::NotPermitted(format!(
                    "stored cursor requires at least {min_gas} gas units"
                ))
                .into());
            }
        }
    }
    // Execute on a captured snapshot using the selected mode, offloaded to
    // a blocking worker pool to avoid tying up the server thread.
    let state_cloned = Arc::clone(&state);
    let store_cloned = live_query_store.clone();
    let authority_cloned = authority.clone();
    #[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
    let continue_budget = match &request {
        iroha_data_model::query::QueryRequest::Continue(cursor) => cursor.gas_budget,
        _ => None,
    };
    let stored_start_budget = match &request {
        iroha_data_model::query::QueryRequest::Start(_) => opts.gas_units,
        _ => None,
    };
    let count_mode = match opts.count_mode.as_deref() {
        Some("exact") => QueryCountMode::Exact,
        Some("bounded") | None => QueryCountMode::Bounded,
        Some(other) => {
            iroha_logger::warn!(other, "unknown count_mode override; using bounded");
            QueryCountMode::Bounded
        }
    };
    let mut limits =
        QueryLimits::new(app_query_limits().max_fetch_size).with_count_mode(count_mode);
    if let Some((FanoutQueryOutputLimits::Singular(singular), _, _)) = fanout_execution.as_ref() {
        limits = limits.with_singular_output_limits(*singular);
    }
    let resp = crate::panic_recovery::join_recoverable(
        crate::panic_recovery::spawn_blocking_recoverable(move || {
            // A cancelled HTTP future detaches `spawn_blocking`. Keep both the
            // physical-work admission and the shared fanout-memory reservation in
            // this worker until validation and execution have actually stopped.
            let _admission = admission;
            match fanout_execution {
                Some((_, execution_budget, _fanout_reservation)) => {
                    run_on_snapshot_ephemeral_with_budget_arc(
                        &state_cloned,
                        &store_cloned,
                        &authority_cloned,
                        request,
                        limits,
                        execution_budget,
                    )
                }
                None => run_on_snapshot_with_mode_arc_and_start_budget(
                    &state_cloned,
                    &store_cloned,
                    &authority_cloned,
                    request,
                    mode,
                    limits,
                    stored_start_budget,
                ),
            }
        }),
    )
    .await
    .map_err(|e| ValidationFail::InternalError(format!("query worker join error: {e}")))
    .and_then(|r| {
        r.map_err(|e| match e {
            SnapshotQueryError::Validation(v) => v,
            SnapshotQueryError::Execution(exec) => ValidationFail::QueryFailed(exec),
        })
    })?;
    #[cfg(feature = "telemetry")]
    if tel.is_enabled() {
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        let first_batch_ms = matches!(resp, QueryResponse::Iterable(_)).then_some(ms);
        let mut gas_units = [0_u64; 2];
        let mut gas_count = 0_usize;
        if matches!(mode, LaneCursorMode::Stored) {
            if let Some(units) = opts.gas_units {
                gas_units[gas_count] = units;
                gas_count += 1;
            }
            if let Some(units) = continue_budget {
                gas_units[gas_count] = units;
                gas_count += 1;
            }
        }
        let _ = tel.with_metrics(|telemetry| {
            telemetry.observe_torii_query_snapshot(
                mode_label,
                first_batch_ms,
                &gas_units[..gas_count],
            );
        });
    }
    Ok(resp)
}
