//! Exact pre-key preparation and private exchange DATA, without runtime authority.

use super::*;

const PREPARATION_SCHEMA: &str = "iroha.kagemusha.wallet-e1-worker-preparation.v1";
const MAX_PREPARATION: usize = 16 * 1024;

/// Selected immutable pre-key originals retained before any payment key or E5 exists.
/// This checks consistency only; approval and authenticated worker custody belong to the issuer.
#[derive(Clone)]
pub struct VerifierPreparationV1 {
    original: Vec<u8>,
    pub(super) configuration: [u8; 32],
    pub(super) created_at_ms: u64,
    pub(super) expires_at_ms: u64,
    pub(super) policy: KagemushaWalletEnrollmentPolicyV1,
    app: KagemushaWalletAppPolicyV1,
    challenge: KagemushaWalletEnrollmentChallengeV1,
    account: iroha_data_model::account::AccountId,
    asset: KagemushaWalletAssetScopeV1,
}

impl VerifierPreparationV1 {
    /// Derive exact preparation bytes from validated, independently selected pre-key DATA.
    /// # Errors
    /// Invalid dispatch, changed challenge subject/policies, empty configuration or invalid time.
    pub fn from_selected(
        dispatch: &PreKeyDispatchV1,
        challenge: KagemushaWalletEnrollmentChallengeV1,
        created_at_ms: u64,
        configuration: [u8; 32],
    ) -> Result<Self, Error> {
        let expires_at_ms = created_at_ms
            .checked_add(dispatch.policy.challenge_lifetime_ms)
            .ok_or(Error("challenge expiry overflow"))?;
        Self::from_selected_bounded(
            dispatch,
            challenge,
            created_at_ms,
            expires_at_ms,
            configuration,
        )
    }

    /// Retain a shorter deadline selected by authenticated issuer session/proof authority.
    /// This trusted source constructor accepts no longer lifetime than the exact policy.
    /// # Errors
    /// Invalid dispatch/subject/configuration, nonpositive interval or a policy lifetime extension.
    pub fn from_selected_bounded(
        dispatch: &PreKeyDispatchV1,
        challenge: KagemushaWalletEnrollmentChallengeV1,
        created_at_ms: u64,
        expires_at_ms: u64,
        configuration: [u8; 32],
    ) -> Result<Self, Error> {
        dispatch.validate().map_err(Error)?;
        dispatch.originals_digest(&challenge).map_err(Error)?;
        dispatch
            .policy
            .require_live_challenge(created_at_ms, created_at_ms)
            .map_err(|_| Error("retained challenge time"))?;
        if expires_at_ms
            .checked_sub(created_at_ms)
            .is_none_or(|duration| {
                duration == 0 || duration > dispatch.policy.challenge_lifetime_ms
            })
        {
            return Err(Error("selected challenge expiry"));
        }
        if configuration == [0; 32] {
            return Err(Error("approved configuration binding"));
        }
        let account =
            norito::encode_canonical(&dispatch.account).map_err(|_| Error("account original"))?;
        if account.is_empty() || account.len() > 4096 {
            return Err(Error("account original bound"));
        }
        let (algorithm, owner) = dispatch
            .account
            .try_signatory()
            .ok_or(Error("account owner"))?
            .to_bytes();
        if algorithm != iroha_crypto::Algorithm::Ed25519 || owner.len() != 32 || owner == [0; 32] {
            return Err(Error("account owner"));
        }
        let original = encode(
            &norito::json!({
                "schema": (PREPARATION_SCHEMA),
                "operation_id": (hex::encode(challenge.challenge_digest())),
                "challenge_transcript_base64": (STANDARD.encode(challenge.transcript())),
                "account_original_base64": (STANDARD.encode(&account)),
                "account_owner_public_hex": (hex::encode(owner)),
                "issued_at_ms": (created_at_ms), "expires_at_ms": (expires_at_ms),
                "platform": (match &dispatch.policy.platform { KagemushaWalletEnrollmentPlatformV1::Android { .. } => "android", KagemushaWalletEnrollmentPlatformV1::Apple { .. } => "apple" }),
                "app_policy_hex": (hex::encode(challenge.app_policy)),
                "enrollment_policy_hex": (hex::encode(challenge.enrollment_policy)),
                "config_sha256": (hex::encode(configuration)),
            }),
            MAX_PREPARATION,
        )?;
        Ok(Self {
            original,
            configuration,
            created_at_ms,
            expires_at_ms,
            policy: dispatch.policy.clone(),
            app: dispatch.app.clone(),
            challenge,
            account: dispatch.account.clone(),
            asset: dispatch.asset.clone(),
        })
    }

    /// Exact immutable preparation to retain before worker dispatch or exposing E1.
    pub fn original(&self) -> &[u8] {
        &self.original
    }

    /// Exact selected configuration digest, not an approval or runtime custody verdict.
    pub fn configuration(&self) -> [u8; 32] {
        self.configuration
    }

    /// Produce a Prepare exchange bound to the retained worker journal incarnation.
    /// # Errors
    /// Empty identities or packet encoding bounds.
    pub fn packet(
        &self,
        incarnation: [u8; 32],
        exchange: [u8; 32],
    ) -> Result<VerifierExchangeV1, Error> {
        VerifierExchangeV1::new(
            self.configuration,
            Some(incarnation),
            exchange,
            Kind::Prepare,
            Contents {
                preparation: Some(&self.original),
                ..Contents::default()
            },
        )
    }

    pub(super) fn require_request(&self, request: &RequestV1) -> Result<(), Error> {
        let body = &request.body;
        if body.challenge != self.challenge
            || body.account != self.account
            || body.asset != self.asset
            || body.app != self.app
            || body.policy != self.policy
        {
            return Err(Error("prepared request binding"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Journal,
    Prepare,
    Complete,
    Recover,
    Inspect,
    RecheckRevocation,
}

#[derive(Default)]
struct Contents<'a> {
    preparation: Option<&'a [u8]>,
    original: Option<&'a [u8]>,
    signature: Option<&'a [u8]>,
    dispatch_time_ms: Option<u64>,
}

/// One exact private packet and its response bindings. This is nonserializable DATA,
/// not an authenticated channel, a journal acknowledgment, or signing authority.
pub struct VerifierExchangeV1 {
    frame: Vec<u8>,
    configuration: [u8; 32],
    incarnation: Option<[u8; 32]>,
    exchange: [u8; 32],
    digest: [u8; 32],
    kind: Kind,
    request_binding: Option<[u8; 32]>,
    dispatch_time_ms: Option<u64>,
}

impl VerifierExchangeV1 {
    fn new(
        configuration: [u8; 32],
        incarnation: Option<[u8; 32]>,
        exchange: [u8; 32],
        kind: Kind,
        contents: Contents<'_>,
    ) -> Result<Self, Error> {
        let Contents {
            preparation,
            original,
            signature,
            dispatch_time_ms,
        } = contents;
        if configuration == [0; 32] || exchange == [0; 32] || incarnation == Some([0; 32]) {
            return Err(Error("empty exchange identity"));
        }
        let action = match kind {
            Kind::Journal => "journal",
            Kind::Prepare => "prepare",
            Kind::Complete => "complete",
            Kind::Recover => "recover",
            Kind::Inspect => "inspect",
            Kind::RecheckRevocation => "recheck_revocation",
        };
        let bytes = encode(
            &norito::json!({
                "schema": (SCHEMA), "version": (1_u16), "exchange_id": (hex::encode(exchange)),
                "action": (action), "journal_incarnation": (incarnation.map(hex::encode)),
                "preparation_base64": (preparation.map(|v| STANDARD.encode(v))),
                "original_base64": (original.map(|v| STANDARD.encode(v))),
                "account_signature_base64": (signature.map(|v| STANDARD.encode(v))),
                "dispatch_time_ms": (dispatch_time_ms),
            }),
            MAX_PACKET,
        )?;
        let digest = Sha256::digest(&bytes).into();
        let mut frame = Vec::with_capacity(bytes.len() + 4);
        frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        frame.extend_from_slice(&bytes);
        Ok(Self {
            frame,
            configuration,
            incarnation,
            exchange,
            digest,
            kind,
            request_binding: None,
            dispatch_time_ms,
        })
    }

    /// Observe the selected worker journal before retaining any preparation.
    /// # Errors
    /// Empty configuration/exchange identity or packet bounds.
    pub fn journal(configuration: [u8; 32], exchange: [u8; 32]) -> Result<Self, Error> {
        Self::new(
            configuration,
            None,
            exchange,
            Kind::Journal,
            Contents::default(),
        )
    }

    /// Complete four-byte-length-prefixed original; retries use fresh exchange identities.
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }

    /// Requested worker journal incarnation, absent only in the initial observation.
    /// The node must compare this DATA with its durably selected preparation incarnation.
    pub fn journal_incarnation(&self) -> Option<[u8; 32]> {
        self.incarnation
    }

    /// Fresh nonzero identifier of this exchange.
    pub fn exchange_id(&self) -> [u8; 32] {
        self.exchange
    }

    /// Action of a Complete, Recover or Inspect exchange; `None` for Journal and Prepare.
    /// With [`Self::exchange_id`] and [`Self::dispatch_time_ms`] it is the selection a node
    /// retains with a terminal reply, so the exact exchange can be rebuilt from the retained
    /// request and the reply checked again against every binding.
    pub fn action(&self) -> Option<ActionV1> {
        match self.kind {
            Kind::Complete => Some(ActionV1::Complete),
            Kind::Recover => Some(ActionV1::Recover),
            Kind::Inspect => Some(ActionV1::Inspect),
            Kind::RecheckRevocation => Some(ActionV1::RecheckRevocation),
            Kind::Journal | Kind::Prepare => None,
        }
    }

    /// Trusted dispatch time of a Complete, Recover or Inspect exchange.
    pub fn dispatch_time_ms(&self) -> Option<u64> {
        self.dispatch_time_ms
    }

    fn checked_response(&self, frame: &[u8]) -> Result<Value, Error> {
        if frame.len() < 4 || frame.len() > MAX_PACKET + 4 {
            return Err(Error("response frame bound"));
        }
        let length =
            u32::from_le_bytes(frame[..4].try_into().map_err(|_| Error("frame prefix"))?) as usize;
        if length != frame.len() - 4 {
            return Err(Error("response frame length"));
        }
        let value = decode(&frame[4..], MAX_PACKET)?;
        fields(
            &value,
            &[
                "schema",
                "version",
                "exchange_id",
                "request_sha256",
                "journal_incarnation",
                "config_sha256",
                "outcome",
                "evidence_base64",
                "refusal_code",
            ],
        )?;
        let incarnation = digest(&value, "journal_incarnation")?;
        if text(&value, "schema")? != SCHEMA
            || integer(&value, "version")? != 1
            || digest(&value, "exchange_id")? != self.exchange
            || digest(&value, "request_sha256")? != self.digest
            || digest(&value, "config_sha256")? != self.configuration
            || incarnation == [0; 32]
            || self
                .incarnation
                .is_some_and(|expected| expected != incarnation)
        {
            return Err(Error("response identity"));
        }
        Ok(value)
    }

    /// Check a journal reply's exact packet/configuration binding and return its incarnation.
    /// # Errors
    /// Wrong exchange type, malformed reply or any unavailable/rejected worker outcome.
    pub fn journal_response(&self, frame: &[u8]) -> Result<[u8; 32], Error> {
        if self.kind != Kind::Journal {
            return Err(Error("exchange kind"));
        }
        let value = self.checked_response(frame)?;
        acknowledgment(&value, "journal")?;
        digest(&value, "journal_incarnation")
    }

    /// Check acknowledgment of this exact preparation in this exact worker journal.
    /// # Errors
    /// Wrong exchange type, substituted reply, or any unsuccessful worker outcome.
    pub fn prepared_response(&self, frame: &[u8]) -> Result<(), Error> {
        if self.kind != Kind::Prepare {
            return Err(Error("exchange kind"));
        }
        acknowledgment(&self.checked_response(frame)?, "prepared")
    }

    pub(super) fn request_response(
        &self,
        request: &VerifierRequestV1,
        frame: &[u8],
    ) -> Result<(Value, u64), Error> {
        if !matches!(
            self.kind,
            Kind::Complete | Kind::Recover | Kind::Inspect | Kind::RecheckRevocation
        ) || self.configuration != request.configuration
            || self.request_binding != Some(request_binding(request))
        {
            return Err(Error("exchange request binding"));
        }
        Ok((
            self.checked_response(frame)?,
            self.dispatch_time_ms.ok_or(Error("dispatch time"))?,
        ))
    }
}

fn request_binding(request: &VerifierRequestV1) -> [u8; 32] {
    let mut hash = Sha256::new();
    for original in [
        &request.preparation.original[..],
        &request.original[..],
        &request.request.account_signature[..],
    ] {
        hash.update((original.len() as u64).to_le_bytes());
        hash.update(original);
    }
    hash.finalize().into()
}

pub(super) fn request_exchange(
    request: &VerifierRequestV1,
    action: ActionV1,
    incarnation: [u8; 32],
    exchange: [u8; 32],
    dispatch_time_ms: u64,
) -> Result<VerifierExchangeV1, Error> {
    if dispatch_time_ms < request.verification_time_ms {
        return Err(Error("dispatch time"));
    }
    let mut value = VerifierExchangeV1::new(
        request.configuration,
        Some(incarnation),
        exchange,
        match action {
            ActionV1::Complete => Kind::Complete,
            ActionV1::Recover => Kind::Recover,
            ActionV1::Inspect => Kind::Inspect,
            ActionV1::RecheckRevocation => Kind::RecheckRevocation,
        },
        Contents {
            preparation: Some(&request.preparation.original),
            original: Some(&request.original),
            signature: Some(&request.request.account_signature),
            dispatch_time_ms: Some(dispatch_time_ms),
        },
    )?;
    value.request_binding = Some(request_binding(request));
    Ok(value)
}

fn acknowledgment(value: &Value, expected: &str) -> Result<(), Error> {
    if text(value, "outcome")? == expected
        && value.get("evidence_base64") == Some(&Value::Null)
        && value.get("refusal_code") == Some(&Value::Null)
    {
        return Ok(());
    }
    // Journal and Prepare exchanges carry no evidence, so they can never refuse an E1.
    match failure(value, None)? {
        OutcomeV1::Unavailable => Err(Error("worker unavailable")),
        _ => Err(Error("worker acknowledgment")),
    }
}

/// Classify a non-evidence reply. `android` is the configured platform of an E5 exchange, and
/// `None` for Journal/Prepare, which never refuse. A refusal carries exactly one closed
/// platform code (1–10) that can occur on that platform; every other reply carries none.
pub(super) fn failure(value: &Value, android: Option<bool>) -> Result<OutcomeV1, Error> {
    if value.get("evidence_base64") != Some(&Value::Null) {
        return Err(Error("failure evidence"));
    }
    let outcome = text(value, "outcome")?;
    if outcome != "refused" {
        if value.get("refusal_code") != Some(&Value::Null) {
            return Err(Error("refusal code without refusal"));
        }
        return match outcome {
            "outcome_unknown" => Ok(OutcomeV1::OutcomeUnknown),
            "unavailable" => Ok(OutcomeV1::Unavailable),
            _ => Err(Error("unknown outcome")),
        };
    }
    let android = android.ok_or(Error("refusal outside verification"))?;
    let code = u16::try_from(integer(value, "refusal_code")?).map_err(|_| Error("refusal code"))?;
    match KagemushaWalletEnrollmentRefusalV1::from_code(code) {
        Some(reason) if !reason.is_eligibility() && reason.applies_to(android) => {
            Ok(OutcomeV1::Refused(reason))
        }
        _ => Err(Error("refusal code")),
    }
}
