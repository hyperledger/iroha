use crate::state::StateTransaction;
use iroha_crypto::Hash;
use iroha_data_model::{
    isi::error::{InstructionExecutionError as Error, InvalidParameterError},
    parameter::CustomParameterId,
    prelude::*,
};
use iroha_model_base::metadata::Metadata;
use ivm::limits::GasScheduleEntry;
/// Default maximum size in bytes for JSON payloads (1 MiB).
pub const DEFAULT_JSON_LIMIT: usize = 1_048_576;
/// Enforce a maximum JSON size for values, consulting a custom parameter if present.
///
/// # Errors
/// Returns an error when the value exceeds the configured or default maximum size.
pub fn enforce_json_size(
    state_transaction: &mut StateTransaction<'_, '_>,
    value: &Json,
    param_name: &str,
    default: usize,
) -> Result<(), Error> {
    let params = state_transaction.world.parameters.get();
    let limit = if let Ok(name) = core::str::FromStr::from_str(param_name)
        && let Some(custom) = params.custom().get(&CustomParameterId(name))
        && let Ok(num) = custom.payload().try_into_any_norito::<u64>()
    {
        usize::try_from(num).unwrap_or(usize::MAX)
    } else {
        default
    };
    if value.get().len() > limit {
        return Err(Error::InvalidParameter(
            InvalidParameterError::SmartContract(format!(
                "Payload too large for {}: {} > {} bytes",
                param_name,
                value.get().len(),
                limit
            )),
        ));
    }
    Ok(())
}
/// Enforce the configured per-value JSON bound for every entry in `metadata`.
///
/// Registration paths use this helper before inserting any state so that they
/// apply the same bound as later `SetKeyValue` operations.
///
/// # Errors
///
/// Returns an error when any metadata value exceeds `max_metadata_value_bytes`.
pub fn enforce_metadata_value_sizes(
    state_transaction: &mut StateTransaction<'_, '_>,
    metadata: &Metadata,
) -> Result<(), Error> {
    for (_, value) in metadata.iter() {
        enforce_json_size(
            state_transaction,
            value,
            "max_metadata_value_bytes",
            DEFAULT_JSON_LIMIT,
        )?;
    }
    Ok(())
}
/// Return the canonical IVM gas schedule entries in opcode order.
#[must_use]
pub fn ivm_gas_schedule_entries() -> Vec<GasScheduleEntry> {
    ivm::limits::gas_schedule_entries()
}
/// Return the deterministic hash of the canonical IVM gas schedule.
#[must_use]
pub fn ivm_gas_schedule_hash() -> Hash {
    ivm::limits::schedule_hash()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_data_model::parameter::{CustomParameter, CustomParameterId, Parameter};
    use std::str::FromStr as _;

    /// A JSON string document of exactly `bytes` bytes.
    fn document(bytes: usize) -> Json {
        let value = Json::new("x".repeat(bytes - 2));
        assert_eq!(value.get().len(), bytes, "the fixture has the asked size");
        value
    }

    #[test]
    fn metadata_value_of_exactly_the_bound_is_admitted_and_one_byte_more_is_refused() {
        let state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let header =
            iroha_data_model::block::BlockHeader::new(core::num::NonZeroU64::MIN, None, None, 0, 0);
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        let refused = |error: Error, expected: &str| {
            assert!(
                matches!(
                    &error,
                    Error::InvalidParameter(InvalidParameterError::SmartContract(message))
                        if message == expected
                ),
                "unexpected refusal: {error:?}"
            );
        };

        // No custom parameter is committed: the default applies, and a value of exactly
        // the default is admitted, alone and inside a metadata map.
        let largest = document(DEFAULT_JSON_LIMIT);
        enforce_json_size(
            &mut transaction,
            &largest,
            "max_metadata_value_bytes",
            DEFAULT_JSON_LIMIT,
        )
        .expect("a value of exactly the default bound is admitted");
        let mut metadata = Metadata::default();
        metadata.insert("largest".parse().expect("metadata key"), largest.clone());
        enforce_metadata_value_sizes(&mut transaction, &metadata)
            .expect("metadata with a value of exactly the default bound is admitted");
        // The default is also the largest JSON document the data model can hold, so a
        // value of one byte more than the default does not exist as a `Json`.
        assert_eq!(DEFAULT_JSON_LIMIT, iroha_primitives::json::MAX_JSON_BYTES);
        assert!(Json::try_new("x".repeat(DEFAULT_JSON_LIMIT - 1)).is_err());
        // The comparison refuses one byte above the bound that applies.
        refused(
            enforce_json_size(
                &mut transaction,
                &largest,
                "max_metadata_value_bytes",
                DEFAULT_JSON_LIMIT - 1,
            )
            .expect_err("a value one byte above the applicable bound is refused"),
            "Payload too large for max_metadata_value_bytes: 1048576 > 1048575 bytes",
        );

        // A committed custom parameter replaces the default: exactly its value is
        // admitted and one byte more is refused.
        let name = CustomParameterId::from_str("max_metadata_value_bytes").expect("parameter name");
        transaction
            .world
            .parameters_mut_for_testing()
            .get_mut()
            .set_parameter(Parameter::Custom(CustomParameter::new(
                name,
                Json::new(64_u64),
            )));
        let mut metadata = Metadata::default();
        metadata.insert("exact".parse().expect("metadata key"), document(64));
        enforce_metadata_value_sizes(&mut transaction, &metadata)
            .expect("a value of exactly the committed bound is admitted");
        metadata.insert("over".parse().expect("metadata key"), document(65));
        refused(
            enforce_metadata_value_sizes(&mut transaction, &metadata)
                .expect_err("a value one byte above the committed bound is refused"),
            "Payload too large for max_metadata_value_bytes: 65 > 64 bytes",
        );
    }
}
