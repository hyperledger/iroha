//! Shared admission for closed wallet plans; this module does not accept instructions or sign.

use super::{BoundedTransactionOptions, FeePaymentIntent, Result};

pub(super) fn encode_bounded<T: norito::core::NoritoSerialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>> {
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let length = norito::canonical_frame_len(value)?;
    eyre::ensure!(length <= maximum, "operation frame exceeds its byte bound");
    norito::core::to_bytes_bounded(value, length).map_err(|error| match error {
        norito::core::BoundedEncodeError::Serialization(error)
            if error.decode_resource_error().is_some() =>
        {
            error.into()
        }
        error => eyre::eyre!("bounded operation encoding: {error:?}"),
    })
}

pub(super) fn decode_bounded<T>(bytes: &[u8], maximum: usize) -> Result<T>
where
    T: norito::core::NoritoSerialize + for<'de> norito::core::NoritoDeserialize<'de>,
{
    eyre::ensure!(
        !bytes.is_empty() && bytes.len() <= maximum,
        "operation frame exceeds its byte bound"
    );
    Ok(norito::decode_canonical_with_limits(
        bytes,
        // Raw byte vectors use the same sequence count as typed containers. Their admitted
        // frame is the generic bound; each closed operation validates its typed cardinalities.
        norito::DecodeLimits::new(maximum, maximum, maximum, 16 * 1024 * 1024, 32),
    )?)
}

pub(super) fn validate_options(options: &BoundedTransactionOptions) -> Result<()> {
    // Admit container cardinalities before cloning any caller-controlled fee authorization.
    eyre::ensure!(
        options.max_total_fees.len() <= 16 && options.fee_payment.charge_limits().len() <= 16,
        "operation fee authorization exceeds sixteen entries"
    );
    eyre::ensure!(
        matches!(options.fee_payment, FeePaymentIntent::Authority(_)),
        "operation requires explicit authority-paid fees"
    );
    options.fee_payment.validate()?;
    eyre::ensure!(
        options
            .max_total_fees
            .values()
            .all(|value| !value.is_zero()),
        "operation aggregate fee maxima must be positive"
    );
    Ok(())
}
