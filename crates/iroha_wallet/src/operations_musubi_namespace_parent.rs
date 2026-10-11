//! Fresh-generation-only namespace parent and bounded immutable first-use wallet attempt chain.
//! Ordinary callers open existing custody. This is local retention, not namespace authority.
use super::*;
use iroha_fs::{PrivateDirectory, PublishMode};
use std::{ffi::OsStr, time::Instant};

const SCHEMA: &str = "iroha.wallet.generated-musubi-namespace.v1";
const MAX_PARENT_BYTES: usize = 16 * 1024;
const MAX_WINDOW_MS: u64 = 60_000;
const MAX_ATTEMPTS: u16 = 64;
const ANCHOR: &str = "custody-anchor.nrt";
const MAX_ENTRIES: usize = 3 + 4 * MAX_ATTEMPTS as usize;

#[derive(norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
struct Original {
    schema: String,
    selection: Vec<u8>,
    fee_payment: FeePaymentIntent,
}
#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::musubi_namespace::Authorization")]
struct Authorization {
    ordinal: u16,
    predecessor_retirement: Option<[u8; 32]>,
    selected_at_ms: u64,
    deadline_ms: u64,
}
#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::musubi_namespace::Child")]
struct Child {
    request_sha256: String,
}

#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::musubi_namespace::Retirement")]
struct Retirement {
    ordinal: u16,
    authorization_sha256: [u8; 32],
    request_sha256: Option<String>,
    retired_at_ms: u64,
}
#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_wallet::operations::musubi_namespace::Anchor")]
struct Anchor {
    ordinal: u16,
    authorization_sha256: Option<[u8; 32]>,
    child_request_sha256: Option<String>,
}
struct Attempt {
    authorization: Authorization,
    preparation: Option<VerifiedNativePreparation>,
    retirement: Option<Retirement>,
}
fn name(kind: &str, ordinal: u16) -> String {
    format!("{kind}-{ordinal:04}")
}

/// Held original generated parent and at most64 explicitly linked wallet attempts.
///
/// There is no decode or arbitrary constructor. This local capability excludes concurrent parent
/// mutation; it conveys no chain ownership or permission. Each authorization is immutable. Only
/// exact absent/RequestOnly custody can retire after expiry; payloads and signatures never reset.
pub struct MusubiNamespaceBindingParent<'a> {
    service: &'a AccountService,
    held: Journal,
    directory: PrivateDirectory,
    selection: MusubiNamespaceBindingSelection,
    fee: FeePaymentIntent,
}
impl AccountService {
    /// Initialize the original clock-independent namespace parent during fresh generation only.
    ///
    /// Uses the shared journal atomic publication owner, with no quote, signature or HTTP. The selected
    /// namespace is intent; native execution still authenticates current owner and registry policy.
    /// Ordinary open/recovery never calls this constructor and missing custody is never repaired.
    /// # Errors
    /// Refuses existing/unsafe paths, mismatched identity, invalid fee/binding or resource bounds.
    pub fn initialize_musubi_namespace_binding_parent(
        &self,
        path: &Path,
        selection: &MusubiNamespaceBindingSelection,
        fee: &FeePaymentIntent,
    ) -> Result<()> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        static_selection(&self.config, selection, fee)?;
        let original = Original {
            schema: SCHEMA.into(),
            selection: encode_bounded(selection, MAX_SELECTION_BYTES)?,
            fee_payment: fee.clone(),
        };
        let anchor = Anchor {
            ordinal: 0,
            authorization_sha256: None,
            child_request_sha256: None,
        };
        drop(Journal::create_prepared_with_custody_anchor(
            path,
            &original,
            &encode_bounded(&anchor, MAX_PARENT_BYTES)?,
        )?);
        Ok(())
    }
    /// Open the exact originally provisioned parent, never creating missing state.
    ///
    /// All later records and the original child are audited before returning, including when a
    /// caller intends only to accept an independently read current binding. Missing marked children,
    /// replacement selection, unknown files and malformed histories refuse instead of resetting UTC.
    /// # Errors
    /// Refuses missing/changed custody, original intent/fee mismatch or invalid preparation history.
    pub fn open_musubi_namespace_binding_parent<'a>(
        &'a self,
        path: &Path,
        selection: &MusubiNamespaceBindingSelection,
        fee: &FeePaymentIntent,
    ) -> Result<MusubiNamespaceBindingParent<'a>> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        static_selection(&self.config, selection, fee)?;
        let held = Journal::open(path)?;
        let original: Original = held.read_operation()?;
        eyre::ensure!(
            original.schema == SCHEMA
                && original.selection == encode_bounded(selection, MAX_SELECTION_BYTES)?
                && original.fee_payment == *fee,
            "original namespace parent selection differs"
        );
        let result = MusubiNamespaceBindingParent {
            service: self,
            directory: PrivateDirectory::open(held.path())?,
            held,
            selection: selection.clone(),
            fee: fee.clone(),
        };
        result.inspect(Instant::now() + std::time::Duration::from_secs(1))?;
        Ok(result)
    }
}
fn static_selection(
    config: &Config,
    selection: &MusubiNamespaceBindingSelection,
    fee: &FeePaymentIntent,
) -> Result<()> {
    eyre::ensure!(
        fee.charge_limits().len() <= 16,
        "namespace fee intent exceeds bound"
    );
    encode_bounded(fee, MAX_SELECTION_BYTES)?;
    fee.validate()?;
    eyre::ensure!(
        matches!(fee, FeePaymentIntent::Authority(_)),
        "generated namespace requires owner-paid fees"
    );
    encode_bounded(selection, MAX_SELECTION_BYTES)?;
    // Reuse the closed instruction validator without sampling or retaining a signing interval.
    Plan {
        selection: selection.clone(),
        validated_at_unix_ms: 1,
        deadline_unix_ms: 2,
    }
    .instructions(config)?;
    Ok(())
}
impl MusubiNamespaceBindingParent<'_> {
    fn options(&self, deadline: Instant) -> Result<BoundedTransactionOptions> {
        let mut maxima = BTreeMap::new();
        for limit in self.fee.charge_limits() {
            let entry = maxima
                .entry(limit.asset_definition_id.clone())
                .or_insert_with(Quantity::zero);
            *entry = entry
                .checked_add(&limit.max_amount)
                .map_err(|error| eyre!(error).wrap_err("namespace fee ceiling overflow"))?;
        }
        Ok(BoundedTransactionOptions {
            fee_payment: self.fee.clone(),
            max_total_fees: maxima,
            deadline,
        })
    }
    fn read<T: norito::core::NoritoSerialize + for<'de> norito::core::NoritoDeserialize<'de>>(
        &self,
        name: &str,
    ) -> Result<Option<T>> {
        self.directory
            .read_optional(name, MAX_PARENT_BYTES)?
            .map(|bytes| decode_bounded(&bytes, MAX_PARENT_BYTES))
            .transpose()
    }
    fn request(
        &self,
        original: &Authorization,
        deadline: Instant,
    ) -> Result<MusubiNamespaceBindingRequest> {
        Ok(MusubiNamespaceBindingRequest {
            selection: self.selection.clone(),
            deadline_unix_ms: original.deadline_ms,
            options: self.options(deadline)?,
        })
    }
    fn digest<T: norito::core::NoritoSerialize>(value: &T) -> Result<[u8; 32]> {
        use sha2::{Digest as _, Sha256};
        Ok(Sha256::digest(encode_bounded(value, MAX_PARENT_BYTES)?).into())
    }
    fn audit(&self, deadline: Instant) -> Result<Vec<Attempt>> {
        let _profile =
            ChainDiscriminantGuard::enter(self.service.config.account_chain_discriminant);
        let original: Original = self.held.read_operation()?;
        eyre::ensure!(
            original.schema == SCHEMA
                && original.selection == encode_bounded(&self.selection, MAX_SELECTION_BYTES)?
                && original.fee_payment == self.fee,
            "namespace parent changed"
        );
        let entries = self.directory.entries(MAX_ENTRIES)?;
        let anchor: Anchor = self
            .read(ANCHOR)?
            .ok_or_else(|| eyre!("required namespace custody anchor is missing"))?;
        eyre::ensure!(
            anchor.ordinal <= MAX_ATTEMPTS
                && ((anchor.ordinal == 0
                    && anchor.authorization_sha256.is_none()
                    && anchor.child_request_sha256.is_none())
                    || (anchor.ordinal > 0 && anchor.authorization_sha256.is_some())),
            "invalid namespace custody anchor"
        );
        let mut referenced_max = 0u16;
        for entry in &entries {
            if entry == OsStr::new("lock")
                || entry == OsStr::new("operation.json")
                || entry == OsStr::new(ANCHOR)
            {
                continue;
            }
            let value = entry
                .to_str()
                .ok_or_else(|| eyre!("invalid namespace parent name"))?;
            let (kind, index) = value
                .split_once('-')
                .ok_or_else(|| eyre!("unknown namespace parent material"))?;
            let index: u16 = index.parse()?;
            eyre::ensure!(
                ["authorization", "child", "transaction", "retirement"].contains(&kind)
                    && (1..=MAX_ATTEMPTS).contains(&index)
                    && value == name(kind, index),
                "unknown namespace parent material"
            );
            referenced_max = referenced_max.max(index);
        }
        eyre::ensure!(
            referenced_max >= anchor.ordinal && referenced_max <= anchor.ordinal.saturating_add(1),
            "namespace inventory differs from retained high-water anchor"
        );
        let mut attempts = Vec::new();
        let allocation = usize::from(referenced_max)
            .checked_mul(std::mem::size_of::<Attempt>())
            .ok_or_else(|| eyre!("namespace attempt allocation overflow"))?;
        norito::core::reserve_decode_allocation(allocation)?;
        attempts.try_reserve_exact(usize::from(referenced_max))?;
        for ordinal in 1..=referenced_max {
            let authorization: Authorization = self
                .read(&name("authorization", ordinal))?
                .ok_or_else(|| eyre!("namespace attempt chain has a hole"))?;
            let previous = attempts
                .last()
                .map(|prior: &Attempt| {
                    prior
                        .retirement
                        .as_ref()
                        .ok_or_else(|| eyre!("namespace predecessor is not retired"))
                        .and_then(Self::digest)
                })
                .transpose()?;
            eyre::ensure!(
                authorization.ordinal == ordinal
                    && authorization.predecessor_retirement == previous
                    && authorization.selected_at_ms > 0
                    && authorization.deadline_ms > authorization.selected_at_ms
                    && authorization.deadline_ms - authorization.selected_at_ms <= MAX_WINDOW_MS,
                "invalid original namespace attempt"
            );
            if let Some(prior) = attempts.last() {
                eyre::ensure!(
                    authorization.selected_at_ms
                        >= prior.retirement.as_ref().unwrap().retired_at_ms,
                    "namespace authorization regressed before retirement"
                );
            }
            if ordinal == anchor.ordinal {
                eyre::ensure!(
                    anchor.authorization_sha256 == Some(Self::digest(&authorization)?),
                    "namespace anchor selects another original authorization"
                );
            }
            let child: Option<Child> = self.read(&name("child", ordinal))?;
            let has_wallet = entries
                .iter()
                .any(|entry| entry == OsStr::new(&name("transaction", ordinal)));
            let preparation = if has_wallet {
                let request = self.request(&authorization, deadline)?;
                let value = self.service.inspect_musubi_namespace_binding_preparation(
                    &self.directory.path().join(name("transaction", ordinal)),
                    &request,
                )?;
                if let Some(child) = &child {
                    eyre::ensure!(
                        value.request_sha256() == Some(child.request_sha256.as_str()),
                        "namespace child request changed"
                    );
                } else {
                    eyre::ensure!(
                        matches!(
                            value.phase(),
                            NativePreparationPhase::RequestOnly | NativePreparationPhase::Retired
                        ),
                        "unmarked namespace child progressed beyond request-only"
                    );
                }
                Some(value)
            } else {
                eyre::ensure!(child.is_none(), "original namespace child is missing");
                None
            };
            if ordinal == anchor.ordinal {
                match &anchor.child_request_sha256 {
                    Some(hash) => eyre::ensure!(
                        child
                            .as_ref()
                            .is_some_and(|marker| &marker.request_sha256 == hash)
                            && preparation
                                .as_ref()
                                .is_some_and(|value| value.request_sha256() == Some(hash.as_str())),
                        "anchored namespace child disappeared or changed"
                    ),
                    None => eyre::ensure!(
                        preparation.as_ref().is_none_or(|value| matches!(
                            value.phase(),
                            NativePreparationPhase::RequestOnly | NativePreparationPhase::Retired
                        )),
                        "unanchored namespace child advanced"
                    ),
                }
            }
            let retirement: Option<Retirement> = self.read(&name("retirement", ordinal))?;
            if ordinal > anchor.ordinal {
                eyre::ensure!(
                    preparation.is_none() && retirement.is_none() && child.is_none(),
                    "unanchored namespace attempt has effects or child custody"
                );
            }
            if let Some(retired) = &retirement {
                eyre::ensure!(
                    retired.ordinal == ordinal
                        && retired.authorization_sha256 == Self::digest(&authorization)?
                        && retired.retired_at_ms >= authorization.deadline_ms,
                    "namespace retirement precedes original expiry"
                );
                match &preparation {
                    Some(value) => eyre::ensure!(
                        value.phase() == NativePreparationPhase::Retired
                            && value.request_sha256() == retired.request_sha256.as_deref(),
                        "namespace retirement lacks exact wallet receipt"
                    ),
                    None => eyre::ensure!(
                        retired.request_sha256.is_none(),
                        "namespace retirement lost its wallet child"
                    ),
                }
            }
            attempts.push(Attempt {
                authorization,
                preparation,
                retirement,
            });
        }
        eyre::ensure!(
            self.directory.entries(MAX_ENTRIES)? == entries,
            "namespace parent inventory changed"
        );
        Ok(attempts)
    }
    /// Inspect the complete bounded attempt chain without HTTP, creation or retirement.
    /// `None` means the existing original parent has no child in its selected final attempt.
    /// # Errors
    /// Refuses holes, changed predecessors, unmarked later phases or missing retained history.
    pub fn inspect(&self, deadline: Instant) -> Result<Option<VerifiedNativePreparation>> {
        Ok(self
            .audit(deadline)?
            .pop()
            .and_then(|attempt| attempt.preparation))
    }
    fn retire(&self, attempt: &mut Attempt, deadline: Instant) -> Result<()> {
        let now = current_unix_ms()?;
        eyre::ensure!(
            deadline > Instant::now() && now >= attempt.authorization.deadline_ms,
            "namespace attempt is not eligible for expired unsigned retirement"
        );
        let hash = match &attempt.preparation {
            Some(value) if value.phase() == NativePreparationPhase::RequestOnly => {
                let request = self.request(&attempt.authorization, deadline)?;
                let retired = self.service.retire_musubi_namespace_binding_unprepared(
                    &self
                        .directory
                        .path()
                        .join(name("transaction", attempt.authorization.ordinal)),
                    &request,
                )?;
                Some(retired.request_sha256().to_owned())
            }
            Some(value) if value.phase() == NativePreparationPhase::Retired => Some(
                value
                    .request_sha256()
                    .ok_or_else(|| eyre!("retired namespace request hash absent"))?
                    .to_owned(),
            ),
            None => None,
            _ => eyre::bail!("quoted or signed namespace attempt cannot retire"),
        };
        let retired = Retirement {
            ordinal: attempt.authorization.ordinal,
            authorization_sha256: Self::digest(&attempt.authorization)?,
            request_sha256: hash,
            retired_at_ms: now,
        };
        self.directory.write_atomic(
            name("retirement", retired.ordinal),
            &encode_bounded(&retired, MAX_PARENT_BYTES)?,
            PublishMode::CreateNew,
        )?;
        attempt.retirement = Some(retired);
        Ok(())
    }
    fn anchor(&self, authorization: &Authorization) -> Result<()> {
        let current: Anchor = self
            .read(ANCHOR)?
            .ok_or_else(|| eyre!("namespace custody anchor missing"))?;
        let digest = Self::digest(authorization)?;
        if current.ordinal == authorization.ordinal {
            eyre::ensure!(
                current.authorization_sha256 == Some(digest),
                "namespace anchor changed"
            );
            return Ok(());
        }
        eyre::ensure!(
            current.ordinal.checked_add(1) == Some(authorization.ordinal),
            "namespace anchor ordinal changed"
        );
        let next = Anchor {
            ordinal: authorization.ordinal,
            authorization_sha256: Some(digest),
            child_request_sha256: None,
        };
        self.directory.write_atomic(
            ANCHOR,
            &encode_bounded(&next, MAX_PARENT_BYTES)?,
            PublishMode::Replace,
        )?;
        Ok(())
    }

    fn anchor_child(&self, ordinal: u16, hash: &str) -> Result<()> {
        let mut anchor: Anchor = self
            .read(ANCHOR)?
            .ok_or_else(|| eyre!("namespace custody anchor missing"))?;
        eyre::ensure!(
            anchor.ordinal == ordinal,
            "namespace child selected another attempt"
        );
        match &anchor.child_request_sha256 {
            Some(original) => {
                eyre::ensure!(original == hash, "namespace anchored child hash changed")
            }
            None => {
                anchor.child_request_sha256 = Some(hash.to_owned());
                self.directory.write_atomic(
                    ANCHOR,
                    &encode_bounded(&anchor, MAX_PARENT_BYTES)?,
                    PublishMode::Replace,
                )?;
            }
        }
        Ok(())
    }

    /// Advance an exact original or explicitly authorize one bounded successor of expired unsigned custody.
    ///
    /// A newly invoked caller supplies fresh finite UTC only when there is no attempt or the prior
    /// one has expired without any payload/signature. Retirement is durable and the successor
    /// commits its exact digest. Quoted/signed attempts retain the old UTC and wire. At most64
    /// attempts exist; reaching the bound refuses without deleting or weakening any history.
    /// # Errors
    /// Refuses incomplete history, resource/attempt bounds, invalid current authorization or I/O.
    pub fn advance(&self, deadline_unix_ms: u64, deadline: Instant) -> Result<OperationReport> {
        eyre::ensure!(deadline > Instant::now(), "namespace call deadline elapsed");
        let mut attempts = self.audit(deadline)?;
        if let Some(last) = attempts.last() {
            self.anchor(&last.authorization)?;
        }
        if let Some(last) = attempts.last_mut() {
            if last.retirement.is_none()
                && current_unix_ms()? >= last.authorization.deadline_ms
                && last.preparation.as_ref().is_none_or(|value| {
                    matches!(
                        value.phase(),
                        NativePreparationPhase::RequestOnly | NativePreparationPhase::Retired
                    )
                })
            {
                // Validate new caller authorization before changing even an unsigned predecessor.
                let now = current_unix_ms()?;
                eyre::ensure!(
                    last.authorization.ordinal < MAX_ATTEMPTS
                        && deadline > Instant::now()
                        && deadline_unix_ms > now
                        && deadline_unix_ms - now <= MAX_WINDOW_MS,
                    "namespace successor authorization unavailable"
                );
                self.retire(last, deadline)?;
            }
        }
        let new_attempt = attempts.last().is_none_or(|last| last.retirement.is_some());
        if new_attempt {
            let now = current_unix_ms()?;
            eyre::ensure!(
                attempts.len() < usize::from(MAX_ATTEMPTS)
                    && deadline > Instant::now()
                    && deadline_unix_ms > now
                    && deadline_unix_ms - now <= MAX_WINDOW_MS,
                "namespace requires a bounded fresh UTC window and available attempt"
            );
            let ordinal = u16::try_from(attempts.len() + 1)?;
            let previous = attempts
                .last()
                .and_then(|prior| prior.retirement.as_ref())
                .map(Self::digest)
                .transpose()?;
            let authorization = Authorization {
                ordinal,
                predecessor_retirement: previous,
                selected_at_ms: now,
                deadline_ms: deadline_unix_ms,
            };
            self.directory.write_atomic(
                name("authorization", ordinal),
                &encode_bounded(&authorization, MAX_PARENT_BYTES)?,
                PublishMode::CreateNew,
            )?;
            attempts.push(Attempt {
                authorization,
                preparation: None,
                retirement: None,
            });
        }
        let last = attempts
            .pop()
            .ok_or_else(|| eyre!("namespace attempt absent"))?;
        self.anchor(&last.authorization)?;
        let ordinal = last.authorization.ordinal;
        let request = self.request(&last.authorization, deadline)?;
        let path = self.directory.path().join(name("transaction", ordinal));
        let phase = match last.preparation {
            Some(value) => value,
            None => self
                .service
                .retain_musubi_namespace_binding_request(&request, &path)?,
        };
        if self.read::<Child>(&name("child", ordinal))?.is_none() {
            eyre::ensure!(
                phase.phase() == NativePreparationPhase::RequestOnly,
                "only an original request establishes child custody"
            );
            let marker = Child {
                request_sha256: phase
                    .request_sha256()
                    .ok_or_else(|| eyre!("original request hash absent"))?
                    .to_owned(),
            };
            self.directory.write_atomic(
                name("child", ordinal),
                &encode_bounded(&marker, MAX_PARENT_BYTES)?,
                PublishMode::CreateNew,
            )?;
        }
        self.anchor_child(
            ordinal,
            phase
                .request_sha256()
                .ok_or_else(|| eyre!("namespace original request hash missing"))?,
        )?;
        self.inspect(deadline)?;
        self.service
            .prepare_musubi_namespace_binding(&request, &path)?;
        self.service
            .submit_musubi_namespace_binding(&path, &request)
    }
}

#[cfg(test)]
#[path = "operations_musubi_namespace_parent_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "operations_musubi_namespace_parent_optional_tests.rs"]
mod optional_tests;
