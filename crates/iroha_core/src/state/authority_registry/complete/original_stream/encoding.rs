//! Exact funded bare Norito frames retained by one original source attempt.

use super::CaptureError;
#[cfg(test)]
use super::CaptureLimits;
use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_crypto::Hash;
#[cfg(test)]
use norito::codec::Encode;
use std::io::{self, Write};

/// One exact canonical frame. It is deliberately neither serializable nor cloneable.
pub(super) struct Frame(ChargedBuffer<u8>);
impl Frame {
    pub(super) fn bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
    #[cfg(test)]
    pub(super) fn encode<T: Encode>(
        value: &T,
        limits: CaptureLimits,
        budget: &AllocationBudget,
    ) -> Result<Self, CaptureError> {
        Self::from_writer(limits.max_payload_bytes, budget, |writer| {
            super::bare(value, writer)
        })
    }
    pub(super) fn from_writer(
        max_bytes: usize,
        budget: &AllocationBudget,
        encode: impl Fn(&mut dyn Write) -> Result<(), norito::core::Error>,
    ) -> Result<Self, CaptureError> {
        let mut length = 0;
        let mut exceeded = false;
        let mut measured = Ok(());
        let digest = Hash::new_from_writer(|writer| {
            let mut bounded = Measure {
                inner: writer,
                length: &mut length,
                limit: max_bytes,
                exceeded: &mut exceeded,
            };
            measured = encode(&mut bounded);
            Ok(())
        })
        .map_err(CaptureError::EncodingIo)?;
        if exceeded {
            return Err(CaptureError::PayloadLimit);
        }
        measured.map_err(CaptureError::Codec)?;
        let mut result = Self(ChargedBuffer::new(length, budget)?);
        let mut writer = ExactWrite {
            frame: &mut result,
            failed: false,
        };
        // Preserve a propagated original codec error before checking for a writer
        // refusal that the encoder swallowed. The flag belongs only to this pass.
        encode(&mut writer).map_err(CaptureError::Codec)?;
        if writer.failed {
            return Err(CaptureError::EncodingChanged);
        }
        if result.bytes().len() != length || Hash::new(result.bytes()) != digest {
            return Err(CaptureError::EncodingChanged);
        }
        Ok(result)
    }
}
struct ExactWrite<'a> {
    frame: &'a mut Frame,
    failed: bool,
}
impl Write for ExactWrite<'_> {
    fn write(&mut self, value: &[u8]) -> io::Result<usize> {
        if let Err(original) = self.frame.0.append(value) {
            self.failed = true;
            return Err(original);
        }
        Ok(value.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Measure<'a> {
    inner: &'a mut dyn Write,
    length: &'a mut usize,
    limit: usize,
    exceeded: &'a mut bool,
}
impl Write for Measure<'_> {
    fn write(&mut self, value: &[u8]) -> io::Result<usize> {
        let Some(next) = self
            .length
            .checked_add(value.len())
            .filter(|next| *next <= self.limit)
        else {
            *self.exceeded = true;
            return Err(io::Error::other(
                "original canonical payload exceeds local allowance",
            ));
        };
        self.inner.write_all(value)?;
        *self.length = next;
        Ok(value.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
