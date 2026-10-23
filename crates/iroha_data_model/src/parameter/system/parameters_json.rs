//! One canonical parameter record walk with ordinary and original-pool destinations.
//!
//! This is allocation custody, not signed source or State publication authority.
//! The enclosing owner funds source bytes and its own control/record storage.

use super::{
    BlockParameters, Parameters, SmartContractParameters, SumeragiParameters,
    TransactionParameters, defaults,
};
use crate::parameter::{
    custom::{
        CustomParameters, CustomParametersAdmissionError, CustomParametersJsonAdmissionError,
    },
    execution_output::ExecutionOutputPolicyV1,
    fastpq_source::{FastpqMandatorySourcePolicyV1, FastpqSourceLimitsV1, FastpqSourcePolicyV1},
};
use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer, ChargedBufferError};
use iroha_crypto::Algorithm;
use norito::json::{self, JsonDeserialize};
use std::{
    alloc::Layout,
    num::{NonZeroU16, NonZeroU32, NonZeroU64},
};

/// Original JSON, logical work, finite-pool or physical-allocation refusal.
#[derive(Debug, thiserror::Error)]
pub enum ParametersJsonAdmissionError {
    /// Original JSON error, retaining any opaque decoder observer identity.
    #[error(transparent)]
    Json(#[from] json::Error),
    /// Original allocation refusal before a backing array or string is used.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
    /// Original directly decoded custom-map ownership refusal.
    #[error(transparent)]
    Custom(CustomParametersJsonAdmissionError),
    /// Original refusal while retaining the empty protocol-default custom map.
    #[error(transparent)]
    RetainCustom(CustomParametersAdmissionError),
}
impl From<CustomParametersJsonAdmissionError> for ParametersJsonAdmissionError {
    fn from(error: CustomParametersJsonAdmissionError) -> Self {
        match error {
            CustomParametersJsonAdmissionError::Json(error) => Self::Json(error),
            error => Self::Custom(error),
        }
    }
}

/// Opaque exact backing custody of the canonical Sumeragi algorithm array.
///
/// Custom-map entries, IDs and shared JSON leaves own their own custody. They are
/// deliberately not charged a second time here. This ledger has no public constructor.
pub struct ParametersCustody {
    algorithms: AllocationCharge,
}
impl ParametersCustody {
    /// Whether the algorithm backing was funded by this original pool.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.algorithms.belongs_to(budget)
    }
    /// Exact retained bytes here, excluding the separately self-owned custom map.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.algorithms.layout().size()
    }
}

/// Immutable canonical parameters paired with their exact allocation ownership.
///
/// Ordinary clones from the borrow do not inherit this array ledger. JSON leaves
/// retain their own shared charge even if a caller clones one out of the borrow.
/// No mutable borrow, Clone or safe ordinary-value extraction is exposed.
pub struct AdmittedParameters {
    // Field order retires all physical values before their corresponding credits.
    value: Parameters,
    custody: ParametersCustody,
}
impl AdmittedParameters {
    /// Decode directly from the original parser and original allocation pool.
    ///
    /// Every child uses the same object/scalar/array kernel as ordinary decoding.
    /// Escaped keys and algorithm text are funded scratch; the algorithm array
    /// and custom values go directly into their retained destinations. No Value
    /// tree, reserialized document or unadmitted intermediate graph is created.
    /// The caller keeps the original decoder context and checks document completion.
    /// # Errors
    /// Preserves the original refusal; every partial owner retires on failure.
    pub fn try_decode_json(
        parser: &mut json::Parser<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, ParametersJsonAdmissionError> {
        let Parts { value, custody } = parameters(parser, &Admitted { budget })?;
        Ok(Self {
            value,
            custody: ParametersCustody {
                algorithms: custody,
            },
        })
    }
    /// Construct the maintained protocol defaults directly in original-pool custody.
    ///
    /// The default algorithm slice is shared with ordinary default construction;
    /// no temporary Vec or JSON document is built. This does not supply a missing
    /// required genesis policy or authenticate an otherwise empty State.
    /// # Errors
    /// Preserves finite-pool, native allocator and cumulative decoder refusals.
    pub fn try_protocol_default(
        budget: &AllocationBudget,
    ) -> Result<Self, ParametersJsonAdmissionError> {
        let destination = Admitted { budget };
        let sumeragi = default_sumeragi(&destination)?;
        let custom = destination.empty_custom()?;
        let Parts {
            value: sumeragi,
            custody,
        } = sumeragi;
        Ok(Self {
            value: Parameters {
                sumeragi,
                block: BlockParameters::default(),
                transaction: TransactionParameters::default(),
                executor: SmartContractParameters::default(),
                smart_contract: SmartContractParameters::default(),
                custom,
            },
            custody: ParametersCustody {
                algorithms: custody,
            },
        })
    }
    /// Borrow canonical values without separating the ledger from their backing.
    #[must_use]
    pub fn get(&self) -> &Parameters {
        &self.value
    }
    /// Check the exact original pool of both array and self-custodial custom graph.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.custody.belongs_to(budget) && self.value.custom.belongs_to(budget)
    }
    /// Move canonical bytes and their opaque ledger into an enclosing immutable owner.
    ///
    /// # Safety
    /// The caller must retain custody until the unchanged algorithm Vec has been
    /// destroyed, must not mutate/reallocate that Vec, and must not refund its
    /// charge while a physical backing remains. Custom values keep their own
    /// charge; the enclosing owner must preserve the same pool and destruction order.
    #[allow(unsafe_code)]
    pub unsafe fn into_allocation_parts(self) -> (Parameters, ParametersCustody) {
        (self.value, self.custody)
    }
}

// Also protects partial records: value is always destroyed before its own ledger.
struct Parts<T, C> {
    value: T,
    custody: C,
}
fn invalid(message: &'static str) -> json::Error {
    json::Error::WithPos {
        msg: message,
        byte: 0,
        line: 1,
        col: 1,
    }
}
fn key_text<'a, T: AsRef<str>>(key: &'a json::KeyRef<'_, T>) -> &'a str {
    match key {
        json::KeyRef::Borrowed(text) => text,
        json::KeyRef::Owned(text) => text.as_ref(),
    }
}
trait Destination {
    type Error: From<json::Error>;
    type Text: AsRef<str>;
    type Algorithms;
    type Custody;
    fn key<'a>(
        &self,
        object: &mut json::MapVisitor<'a, '_>,
    ) -> Result<Option<json::KeyRef<'a, Self::Text>>, Self::Error>;
    fn string(&self, parser: &mut json::Parser<'_>) -> Result<Self::Text, Self::Error>;
    fn reserve_algorithms(&self, count: usize) -> Result<Self::Algorithms, Self::Error>;
    fn push_algorithm(array: &mut Self::Algorithms, value: Algorithm);
    fn finish_algorithms(array: Self::Algorithms) -> Parts<Vec<Algorithm>, Self::Custody>;
    fn custom(&self, parser: &mut json::Parser<'_>) -> Result<CustomParameters, Self::Error>;
    fn empty_custom(&self) -> Result<CustomParameters, Self::Error>;
}
struct Ordinary;
impl Destination for Ordinary {
    type Error = json::Error;
    type Text = String;
    type Algorithms = Vec<Algorithm>;
    type Custody = ();
    fn key<'a>(
        &self,
        object: &mut json::MapVisitor<'a, '_>,
    ) -> Result<Option<json::KeyRef<'a>>, Self::Error> {
        object.next_key()
    }
    fn string(&self, parser: &mut json::Parser<'_>) -> Result<String, Self::Error> {
        parser.parse_string()
    }
    fn reserve_algorithms(&self, count: usize) -> Result<Vec<Algorithm>, Self::Error> {
        let layout = Layout::array::<Algorithm>(count)
            .map_err(|_| invalid("algorithm array length overflow"))?;
        norito::core::reserve_decode_allocation(layout.size())
            .map_err(json::Error::from_decode_resource)?;
        let mut values = Vec::new();
        values.try_reserve_exact(count).map_err(|_| {
            json::Error::from_decode_resource(norito::Error::AllocationFailed {
                bytes: u64::try_from(layout.size()).unwrap_or(u64::MAX),
            })
        })?;
        Ok(values)
    }
    fn push_algorithm(array: &mut Vec<Algorithm>, value: Algorithm) {
        array.push(value);
    }
    fn finish_algorithms(value: Vec<Algorithm>) -> Parts<Vec<Algorithm>, ()> {
        Parts { value, custody: () }
    }
    fn custom(&self, parser: &mut json::Parser<'_>) -> Result<CustomParameters, Self::Error> {
        CustomParameters::json_deserialize(parser)
    }
    fn empty_custom(&self) -> Result<CustomParameters, Self::Error> {
        Ok(CustomParameters::new())
    }
}
struct Text(ChargedBuffer<u8>);
impl AsMut<[u8]> for Text {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}
impl AsRef<str> for Text {
    fn as_ref(&self) -> &str {
        std::str::from_utf8(self.0.as_slice()).expect("the shared string parser writes UTF-8")
    }
}
fn text(length: usize, budget: &AllocationBudget) -> Result<Text, ParametersJsonAdmissionError> {
    let mut bytes = ChargedBuffer::new(length, budget)?;
    for _ in 0..length {
        bytes.push_reserved(0);
    }
    Ok(Text(bytes))
}
struct Admitted<'a> {
    budget: &'a AllocationBudget,
}
impl Destination for Admitted<'_> {
    type Error = ParametersJsonAdmissionError;
    type Text = Text;
    type Algorithms = ChargedBuffer<Algorithm>;
    type Custody = AllocationCharge;
    fn key<'a>(
        &self,
        object: &mut json::MapVisitor<'a, '_>,
    ) -> Result<Option<json::KeyRef<'a, Text>>, Self::Error> {
        object.next_key_with_buffer(|len| text(len, self.budget))
    }
    fn string(&self, parser: &mut json::Parser<'_>) -> Result<Text, Self::Error> {
        parser.parse_string_with_buffer(|len| text(len, self.budget))
    }
    fn reserve_algorithms(&self, count: usize) -> Result<Self::Algorithms, Self::Error> {
        let layout = Layout::array::<Algorithm>(count)
            .map_err(|_| invalid("algorithm array length overflow"))?;
        norito::core::reserve_decode_allocation(layout.size())
            .map_err(json::Error::from_decode_resource)?;
        Ok(ChargedBuffer::new(count, self.budget)?)
    }
    fn push_algorithm(array: &mut Self::Algorithms, value: Algorithm) {
        array.push_reserved(value);
    }
    #[allow(unsafe_code)]
    fn finish_algorithms(array: Self::Algorithms) -> Parts<Vec<Algorithm>, AllocationCharge> {
        // SAFETY: the private Parts owner frees this exact unchanged Vec before its
        // ledger. No fallible operation or independently escaping Vec intervenes.
        let (value, custody) = unsafe { array.into_allocation_parts() };
        Parts { value, custody }
    }
    fn custom(&self, parser: &mut json::Parser<'_>) -> Result<CustomParameters, Self::Error> {
        Ok(CustomParameters::try_decode_json(parser, self.budget)?)
    }
    fn empty_custom(&self) -> Result<CustomParameters, Self::Error> {
        CustomParameters::new()
            .try_retain_in(self.budget)
            .map_err(ParametersJsonAdmissionError::RetainCustom)
    }
}

// This macro only lists record fields. MapVisitor owns all object grammar and
// scratch, including duplicate escaped keys, separators, nesting and finalization.
macro_rules! fields {
    ($parser:ident,$destination:ident,$p:ident; $($field:ident => $read:expr),+ $(,)?) => {
        $(let mut $field=None;)+
        let mut object=json::MapVisitor::new($parser)?;
        while let Some(key)=$destination.key(&mut object)? {
            match key_text(&key) {
                $(stringify!($field)=>{
                    if $field.is_some(){return Err(invalid(concat!("duplicate parameter field: ",stringify!($field))).into());}
                    $field=Some(object.parse_value_with_parser_typed(|$p|$read)?);
                },)+
                _=>return Err(invalid("unknown parameter field").into()),
            }
        }
        object.finish()?;
    }
}
macro_rules! required {
    ($field:ident) => {
        $field.ok_or_else(|| invalid(concat!("missing parameter field: ", stringify!($field))))?
    };
}

// Preserve the earlier canonical record integer domain (including signed zero)
// using the maintained integer kernels. Derived capacity records retain their
// existing strictly unsigned lexical kernel below. No number/Value is restaged.
fn unsigned(parser: &mut json::Parser<'_>) -> Result<u64, json::Error> {
    parser.skip_ws();
    if parser.input().as_bytes().get(parser.position()) == Some(&b'-') {
        u64::try_from(i64::json_deserialize(parser)?)
            .map_err(|_| invalid("expected non-negative integer"))
    } else {
        parser.parse_u64()
    }
}
fn nz64(parser: &mut json::Parser<'_>) -> Result<NonZeroU64, json::Error> {
    NonZeroU64::new(unsigned(parser)?).ok_or_else(|| invalid("expected nonzero u64"))
}
fn nz32(parser: &mut json::Parser<'_>) -> Result<NonZeroU32, json::Error> {
    NonZeroU32::new(u32::try_from(unsigned(parser)?).map_err(|_| invalid("u32 overflow"))?)
        .ok_or_else(|| invalid("expected nonzero u32"))
}
fn nz16(parser: &mut json::Parser<'_>) -> Result<NonZeroU16, json::Error> {
    NonZeroU16::new(u16::try_from(unsigned(parser)?).map_err(|_| invalid("u16 overflow"))?)
        .ok_or_else(|| invalid("expected nonzero u16"))
}
fn byte(parser: &mut json::Parser<'_>) -> Result<u8, json::Error> {
    u8::try_from(unsigned(parser)?).map_err(|_| invalid("u8 overflow"))
}
fn strict32(parser: &mut json::Parser<'_>) -> Result<u32, json::Error> {
    u32::try_from(parser.parse_u64()?).map_err(|_| invalid("u32 overflow"))
}
fn algorithms<D: Destination>(
    parser: &mut json::Parser<'_>,
    destination: &D,
) -> Result<Parts<Vec<Algorithm>, D::Custody>, D::Error> {
    let array = parser.parse_array_with(
        |count| destination.reserve_algorithms(count),
        |parser| {
            let text = destination.string(parser)?;
            text.as_ref()
                .parse::<Algorithm>()
                .map_err(|_| invalid("unknown key algorithm").into())
        },
        D::push_algorithm,
    )?;
    Ok(D::finish_algorithms(array))
}
fn default_algorithms<D: Destination>(
    destination: &D,
) -> Result<Parts<Vec<Algorithm>, D::Custody>, D::Error> {
    let source = defaults::sumeragi::KEY_ALLOWED_ALGORITHMS;
    let mut array = destination.reserve_algorithms(source.len())?;
    for value in source {
        D::push_algorithm(&mut array, *value);
    }
    Ok(D::finish_algorithms(array))
}

fn sumeragi<D: Destination>(
    parser: &mut json::Parser<'_>,
    destination: &D,
) -> Result<Parts<SumeragiParameters, D::Custody>, D::Error> {
    fields!(parser,destination,p;
    block_cadence_ms => nz64(p).map_err(D::Error::from),
    max_clock_drift_ms => unsigned(p).map_err(D::Error::from),
    due_work_max_lag_ms => nz64(p).map_err(D::Error::from),
    key_activation_lead_blocks => unsigned(p).map_err(D::Error::from),
    key_overlap_grace_blocks => unsigned(p).map_err(D::Error::from),
    key_expiry_grace_blocks => unsigned(p).map_err(D::Error::from),
    key_allowed_algorithms => algorithms(p,destination),
    payload_retry_interval_ms => nz64(p).map_err(D::Error::from),
    exec_budget_ms => nz64(p).map_err(D::Error::from),
    apply_budget_ms => nz64(p).map_err(D::Error::from),
    max_block_bytes => nz32(p).map_err(D::Error::from),
    epoch_length_blocks => nz64(p).map_err(D::Error::from),
    demotion_window => nz64(p).map_err(D::Error::from),
    );
    let due_work_max_lag_ms = required!(due_work_max_lag_ms);
    let algorithms = match key_allowed_algorithms {
        Some(value) => value,
        None => default_algorithms(destination)?,
    };
    let Parts {
        value: key_allowed_algorithms,
        custody,
    } = algorithms;
    Ok(Parts {
        value: SumeragiParameters {
            block_cadence_ms: block_cadence_ms.unwrap_or_else(defaults::sumeragi::block_cadence_ms),
            max_clock_drift_ms: max_clock_drift_ms
                .unwrap_or_else(defaults::sumeragi::max_clock_drift_ms),
            due_work_max_lag_ms,
            key_activation_lead_blocks: key_activation_lead_blocks
                .unwrap_or_else(defaults::sumeragi::key_activation_lead_blocks),
            key_overlap_grace_blocks: key_overlap_grace_blocks
                .unwrap_or_else(defaults::sumeragi::key_overlap_grace_blocks),
            key_expiry_grace_blocks: key_expiry_grace_blocks
                .unwrap_or_else(defaults::sumeragi::key_expiry_grace_blocks),
            key_allowed_algorithms,
            payload_retry_interval_ms: payload_retry_interval_ms
                .unwrap_or_else(defaults::sumeragi::payload_retry_interval_ms),
            exec_budget_ms: exec_budget_ms.unwrap_or_else(defaults::sumeragi::exec_budget_ms),
            apply_budget_ms: apply_budget_ms.unwrap_or_else(defaults::sumeragi::apply_budget_ms),
            max_block_bytes: max_block_bytes.unwrap_or_else(defaults::sumeragi::max_block_bytes),
            epoch_length_blocks: epoch_length_blocks
                .unwrap_or_else(defaults::sumeragi::epoch_length_blocks),
            demotion_window: demotion_window.unwrap_or_else(defaults::sumeragi::demotion_window),
        },
        custody,
    })
}
fn default_sumeragi<D: Destination>(
    destination: &D,
) -> Result<Parts<SumeragiParameters, D::Custody>, D::Error> {
    let Parts {
        value: key_allowed_algorithms,
        custody,
    } = default_algorithms(destination)?;
    Ok(Parts {
        value: SumeragiParameters {
            block_cadence_ms: defaults::sumeragi::block_cadence_ms(),
            max_clock_drift_ms: defaults::sumeragi::max_clock_drift_ms(),
            due_work_max_lag_ms: defaults::sumeragi::due_work_max_lag_ms(),
            key_activation_lead_blocks: defaults::sumeragi::key_activation_lead_blocks(),
            key_overlap_grace_blocks: defaults::sumeragi::key_overlap_grace_blocks(),
            key_expiry_grace_blocks: defaults::sumeragi::key_expiry_grace_blocks(),
            key_allowed_algorithms,
            payload_retry_interval_ms: defaults::sumeragi::payload_retry_interval_ms(),
            exec_budget_ms: defaults::sumeragi::exec_budget_ms(),
            apply_budget_ms: defaults::sumeragi::apply_budget_ms(),
            max_block_bytes: defaults::sumeragi::max_block_bytes(),
            epoch_length_blocks: defaults::sumeragi::epoch_length_blocks(),
            demotion_window: defaults::sumeragi::demotion_window(),
        },
        custody,
    })
}

fn block<D: Destination>(
    parser: &mut json::Parser<'_>,
    destination: &D,
) -> Result<BlockParameters, D::Error> {
    fields!(parser,destination,p;
    max_transactions=>nz64(p).map_err(D::Error::from),
    max_time_trigger_invocations=>nz32(p).map_err(D::Error::from),
    execution_output=>self::execution_output(p,destination),
    fastpq_source=>self::fastpq_source(p,destination),
    );
    Ok(BlockParameters {
        max_transactions: max_transactions.unwrap_or_else(defaults::block::max_transactions),
        max_time_trigger_invocations: required!(max_time_trigger_invocations),
        execution_output: required!(execution_output),
        fastpq_source: required!(fastpq_source),
    })
}

fn transaction<D: Destination>(
    parser: &mut json::Parser<'_>,
    destination: &D,
) -> Result<TransactionParameters, D::Error> {
    fields!(parser,destination,p;
    max_signatures=>nz64(p).map_err(D::Error::from),
    max_instructions=>nz64(p).map_err(D::Error::from),
    ivm_bytecode_size=>nz64(p).map_err(D::Error::from),
    max_tx_bytes=>nz64(p).map_err(D::Error::from),
    max_decompressed_bytes=>nz64(p).map_err(D::Error::from),
    max_metadata_depth=>nz16(p).map_err(D::Error::from),
    max_time_to_live_ms=>nz64(p).map_err(D::Error::from),
    require_height_ttl=>p.parse_bool().map_err(D::Error::from),
    require_sequence=>p.parse_bool().map_err(D::Error::from),
    );
    Ok(TransactionParameters {
        max_signatures: max_signatures.unwrap_or_else(defaults::transaction::max_signatures),
        max_instructions: max_instructions.unwrap_or_else(defaults::transaction::max_instructions),
        ivm_bytecode_size: ivm_bytecode_size
            .unwrap_or_else(defaults::transaction::ivm_bytecode_size),
        max_tx_bytes: max_tx_bytes.unwrap_or_else(defaults::transaction::max_tx_bytes),
        max_decompressed_bytes: max_decompressed_bytes
            .unwrap_or_else(defaults::transaction::max_decompressed_bytes),
        max_metadata_depth: max_metadata_depth
            .unwrap_or_else(defaults::transaction::max_metadata_depth),
        max_time_to_live_ms: max_time_to_live_ms
            .unwrap_or_else(defaults::transaction::max_time_to_live_ms),
        require_height_ttl: require_height_ttl.unwrap_or(false),
        require_sequence: require_sequence.unwrap_or(false),
    })
}

fn smart_contract<D: Destination>(
    parser: &mut json::Parser<'_>,
    destination: &D,
) -> Result<SmartContractParameters, D::Error> {
    fields!(parser,destination,p;
    fuel=>nz64(p).map_err(D::Error::from),
    memory=>nz64(p).map_err(D::Error::from),
    execution_depth=>byte(p).map_err(D::Error::from),
    max_output_items=>nz64(p).map_err(D::Error::from),
    max_output_bytes=>nz64(p).map_err(D::Error::from),
    );
    Ok(SmartContractParameters {
        fuel: fuel.unwrap_or_else(defaults::smart_contract::fuel),
        memory: memory.unwrap_or_else(defaults::smart_contract::memory),
        execution_depth: execution_depth.unwrap_or_else(defaults::smart_contract::execution_depth),
        max_output_items: max_output_items
            .unwrap_or_else(defaults::smart_contract::max_output_items),
        max_output_bytes: max_output_bytes
            .unwrap_or_else(defaults::smart_contract::max_output_bytes),
    })
}

fn execution_output<D: Destination>(
    parser: &mut json::Parser<'_>,
    destination: &D,
) -> Result<ExecutionOutputPolicyV1, D::Error> {
    fields!(parser,destination,p;
    max_outputs=>strict32(p).map_err(D::Error::from),
    max_output_bytes=>p.parse_u64().map_err(D::Error::from),
    max_total_output_bytes=>p.parse_u64().map_err(D::Error::from),
    max_executed_wire_bytes=>p.parse_u64().map_err(D::Error::from),
    max_pipeline_triggers=>strict32(p).map_err(D::Error::from),
    max_time_triggers=>strict32(p).map_err(D::Error::from),
    max_time_invocations=>strict32(p).map_err(D::Error::from),
    );
    Ok(ExecutionOutputPolicyV1 {
        max_outputs: required!(max_outputs),
        max_output_bytes: required!(max_output_bytes),
        max_total_output_bytes: required!(max_total_output_bytes),
        max_executed_wire_bytes: required!(max_executed_wire_bytes),
        max_pipeline_triggers: required!(max_pipeline_triggers),
        max_time_triggers: required!(max_time_triggers),
        max_time_invocations: required!(max_time_invocations),
    })
}

fn fastpq_limits<D: Destination>(
    parser: &mut json::Parser<'_>,
    destination: &D,
) -> Result<FastpqSourceLimitsV1, D::Error> {
    fields!(parser,destination,p;
    max_executed_entries=>strict32(p).map_err(D::Error::from),
    max_transcripts=>strict32(p).map_err(D::Error::from),
    max_deltas=>strict32(p).map_err(D::Error::from),
    max_input_transcript_bytes=>p.parse_u64().map_err(D::Error::from),
    max_statement_bytes=>p.parse_u64().map_err(D::Error::from),
    max_total_statement_bytes=>p.parse_u64().map_err(D::Error::from),
    );
    Ok(FastpqSourceLimitsV1 {
        max_executed_entries: required!(max_executed_entries),
        max_transcripts: required!(max_transcripts),
        max_deltas: required!(max_deltas),
        max_input_transcript_bytes: required!(max_input_transcript_bytes),
        max_statement_bytes: required!(max_statement_bytes),
        max_total_statement_bytes: required!(max_total_statement_bytes),
    })
}

fn fastpq_mandatory<D: Destination>(
    parser: &mut json::Parser<'_>,
    destination: &D,
) -> Result<FastpqMandatorySourcePolicyV1, D::Error> {
    fields!(parser,destination,p;
    max_retained_obligations=>strict32(p).map_err(D::Error::from),
    per_obligation=>self::fastpq_limits(p,destination),
    );
    Ok(FastpqMandatorySourcePolicyV1 {
        max_retained_obligations: required!(max_retained_obligations),
        per_obligation: required!(per_obligation),
    })
}

fn fastpq_source<D: Destination>(
    parser: &mut json::Parser<'_>,
    destination: &D,
) -> Result<FastpqSourcePolicyV1, D::Error> {
    fields!(parser,destination,p;
    intrinsic=>self::fastpq_limits(p,destination),
    block=>self::fastpq_limits(p,destination),
    max_native_maintenance_invocations=>strict32(p).map_err(D::Error::from),
    mandatory=>self::fastpq_mandatory(p,destination),
    );
    Ok(FastpqSourcePolicyV1 {
        intrinsic: required!(intrinsic),
        block: required!(block),
        max_native_maintenance_invocations: required!(max_native_maintenance_invocations),
        mandatory: required!(mandatory),
    })
}

fn parameters<D: Destination>(
    parser: &mut json::Parser<'_>,
    destination: &D,
) -> Result<Parts<Parameters, D::Custody>, D::Error> {
    fields!(parser,destination,p;
     sumeragi=>self::sumeragi(p,destination),
     block=>self::block(p,destination),
     transaction=>self::transaction(p,destination),
     executor=>self::smart_contract(p,destination),
     smart_contract=>self::smart_contract(p,destination),
     custom=>destination.custom(p),
    );
    let sumeragi = match sumeragi {
        Some(value) => value,
        None => default_sumeragi(destination)?,
    };
    let custom = match custom {
        Some(value) => value,
        None => destination.empty_custom()?,
    };
    // All remaining work is infallible; do not detach the Vec ledger across a refusal.
    let Parts {
        value: sumeragi,
        custody,
    } = sumeragi;
    Ok(Parts {
        value: Parameters {
            sumeragi,
            block: block.unwrap_or_default(),
            transaction: transaction.unwrap_or_default(),
            executor: executor.unwrap_or_default(),
            smart_contract: smart_contract.unwrap_or_default(),
            custom,
        },
        custody,
    })
}

pub(in crate::parameter) fn decode_parameters(
    parser: &mut json::Parser<'_>,
) -> Result<Parameters, json::Error> {
    Ok(parameters(parser, &Ordinary)?.value)
}

pub(in crate::parameter) fn decode_sumeragi(
    parser: &mut json::Parser<'_>,
) -> Result<SumeragiParameters, json::Error> {
    Ok(sumeragi(parser, &Ordinary)?.value)
}

pub(in crate::parameter) fn decode_block(
    parser: &mut json::Parser<'_>,
) -> Result<BlockParameters, json::Error> {
    block(parser, &Ordinary)
}

pub(in crate::parameter) fn decode_transaction(
    parser: &mut json::Parser<'_>,
) -> Result<TransactionParameters, json::Error> {
    transaction(parser, &Ordinary)
}

pub(in crate::parameter) fn decode_smart_contract(
    parser: &mut json::Parser<'_>,
) -> Result<SmartContractParameters, json::Error> {
    smart_contract(parser, &Ordinary)
}

pub(in crate::parameter) fn decode_execution_output(
    parser: &mut json::Parser<'_>,
) -> Result<ExecutionOutputPolicyV1, json::Error> {
    execution_output(parser, &Ordinary)
}

pub(in crate::parameter) fn decode_fastpq_limits(
    parser: &mut json::Parser<'_>,
) -> Result<FastpqSourceLimitsV1, json::Error> {
    fastpq_limits(parser, &Ordinary)
}

pub(in crate::parameter) fn decode_fastpq_mandatory(
    parser: &mut json::Parser<'_>,
) -> Result<FastpqMandatorySourcePolicyV1, json::Error> {
    fastpq_mandatory(parser, &Ordinary)
}

pub(in crate::parameter) fn decode_fastpq_source(
    parser: &mut json::Parser<'_>,
) -> Result<FastpqSourcePolicyV1, json::Error> {
    fastpq_source(parser, &Ordinary)
}

#[cfg(test)]
mod tests;

impl AdmittedParameters {
    /// Prepare one canonical successor directly from borrowed original values.
    ///
    /// The algorithm array and every custom entry receive their exact original
    /// destination ownership before copying. No ordinary Parameters clone or
    /// mutable retained collection is created. Authorization and predecessor
    /// binding belong to the enclosing State owner.
    /// # Errors
    /// Returns the original allocation or retained collection refusal.
    pub fn try_with_parameter(
        source: &Parameters,
        parameter: &crate::parameter::Parameter,
        budget: &AllocationBudget,
    ) -> Result<Self, ParametersJsonAdmissionError> {
        use crate::parameter::Parameter;
        if let Parameter::Custom(value) = parameter {
            return Self::try_with_custom(source, value, budget);
        }
        let custom = source
            .custom
            .try_retain_in(budget)
            .map_err(ParametersJsonAdmissionError::RetainCustom)?;
        let mut result = Self::copy_with_custom(source, &source.sumeragi, custom, budget)?;
        // Only fixed-size scalar variants enter the maintained authoring setter.
        // The retained custom map is already final and never mutably accessed.
        let scalar = match parameter {
            Parameter::Sumeragi(value) => Some(Parameter::Sumeragi(*value)),
            Parameter::Block(value) => Some(Parameter::Block(*value)),
            Parameter::Transaction(value) => Some(Parameter::Transaction(*value)),
            Parameter::SmartContract(value) => Some(Parameter::SmartContract(*value)),
            Parameter::Executor(value) => Some(Parameter::Executor(*value)),
            Parameter::Custom(_) => None,
        };
        if let Some(scalar) = scalar {
            result.value.set_parameter(scalar);
        }
        Ok(result)
    }
    /// Prepare one custom entry directly from its borrowed authored value.
    /// This is the same custom update kernel used by `try_with_parameter`;
    /// executor reconciliation need not allocate an enum-owned ID clone first.
    ///
    /// # Errors
    /// Preserves original destination ownership and canonical decoder refusals.
    pub fn try_with_custom(
        source: &Parameters,
        value: &crate::parameter::CustomParameter,
        budget: &AllocationBudget,
    ) -> Result<Self, ParametersJsonAdmissionError> {
        let custom = source
            .custom
            .try_with_update(value.id(), Some(value), budget)
            .map_err(ParametersJsonAdmissionError::RetainCustom)?;
        Self::copy_with_custom(source, &source.sumeragi, custom, budget)
    }

    /// Prepare exact custom removal without touching the original map.
    /// Mandatory policy removal is checked by the enclosing projection owner.
    /// # Errors
    /// Preserves original allocation and collection admission failures.
    pub fn try_without_custom(
        source: &Parameters,
        id: &crate::parameter::CustomParameterId,
        budget: &AllocationBudget,
    ) -> Result<Self, ParametersJsonAdmissionError> {
        let custom = source
            .custom
            .try_with_update(id, None, budget)
            .map_err(ParametersJsonAdmissionError::RetainCustom)?;
        Self::copy_with_custom(source, &source.sumeragi, custom, budget)
    }
    /// Prepare a complete Sumeragi successor with exact algorithm backing.
    /// This accepts a borrowed authored family, never a local policy fallback.
    /// # Errors
    /// Preserves exact original-pool/allocator and cumulative decoder refusals.
    pub fn try_with_sumeragi(
        source: &Parameters,
        sumeragi: &SumeragiParameters,
        budget: &AllocationBudget,
    ) -> Result<Self, ParametersJsonAdmissionError> {
        let custom = source
            .custom
            .try_retain_in(budget)
            .map_err(ParametersJsonAdmissionError::RetainCustom)?;
        Self::copy_with_custom(source, sumeragi, custom, budget)
    }
    fn copy_with_custom(
        source: &Parameters,
        sumeragi: &SumeragiParameters,
        custom: CustomParameters,
        budget: &AllocationBudget,
    ) -> Result<Self, ParametersJsonAdmissionError> {
        let destination = Admitted { budget };
        let mut array = destination.reserve_algorithms(sumeragi.key_allowed_algorithms.len())?;
        for algorithm in &sumeragi.key_allowed_algorithms {
            Admitted::push_algorithm(&mut array, *algorithm);
        }
        let Parts {
            value: key_allowed_algorithms,
            custody,
        } = Admitted::finish_algorithms(array);
        // Every non-array member is copied inline; adding a new Sumeragi field
        // requires an explicit choice here rather than silently allocating via Clone.
        let sumeragi = SumeragiParameters {
            block_cadence_ms: sumeragi.block_cadence_ms,
            max_clock_drift_ms: sumeragi.max_clock_drift_ms,
            due_work_max_lag_ms: sumeragi.due_work_max_lag_ms,
            key_activation_lead_blocks: sumeragi.key_activation_lead_blocks,
            key_overlap_grace_blocks: sumeragi.key_overlap_grace_blocks,
            key_expiry_grace_blocks: sumeragi.key_expiry_grace_blocks,
            key_allowed_algorithms,
            payload_retry_interval_ms: sumeragi.payload_retry_interval_ms,
            exec_budget_ms: sumeragi.exec_budget_ms,
            apply_budget_ms: sumeragi.apply_budget_ms,
            max_block_bytes: sumeragi.max_block_bytes,
            epoch_length_blocks: sumeragi.epoch_length_blocks,
            demotion_window: sumeragi.demotion_window,
        };
        Ok(Self {
            value: Parameters {
                sumeragi,
                block: source.block,
                transaction: source.transaction,
                executor: source.executor,
                smart_contract: source.smart_contract,
                custom,
            },
            custody: ParametersCustody {
                algorithms: custody,
            },
        })
    }
}
