//! Completed original `NPoS` policy custody inside the canonical genesis reader.
//!
//! This owner binds an immutable original body and exact instruction coordinate.
//! It retains only completed, admitted policy work; all authentication checks run
//! on every attempt. No caller can install an unchecked decoded policy.

use iroha_allocation::{AllocationBudget, ChargedBufferError};

use super::{AuthenticatedGenesis, GenesisReadError, PolicySource};
use crate::{
    block::SharedSignedBlock,
    parameter::{
        CustomParameter,
        system::{
            AdmittedSumeragiNposParameters, SumeragiNposJsonAdmissionError, SumeragiNposParameters,
        },
    },
};

/// The original genesis validation, decoder, funding or source refusal.
#[derive(Debug, thiserror::Error)]
pub enum OriginalGenesisReadError {
    /// The unchanged canonical genesis authentication failed or refused decoding.
    #[error(transparent)]
    Validation(#[from] GenesisReadError),
    /// Exact original pool or allocator refusal before policy storage exists.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
    /// The caller selected a pool other than the original signed body owner.
    #[error("signed genesis body and policy require the same original allocation pool")]
    ForeignPool,
}
impl From<String> for OriginalGenesisReadError {
    fn from(error: String) -> Self {
        GenesisReadError::from(error).into()
    }
}
impl From<&str> for OriginalGenesisReadError {
    fn from(error: &str) -> Self {
        GenesisReadError::from(error).into()
    }
}
impl From<norito::json::Error> for OriginalGenesisReadError {
    fn from(error: norito::json::Error) -> Self {
        GenesisReadError::from(error).into()
    }
}
impl From<SumeragiNposJsonAdmissionError> for OriginalGenesisReadError {
    fn from(error: SumeragiNposJsonAdmissionError) -> Self {
        match error {
            SumeragiNposJsonAdmissionError::Json(error) => error.into(),
            SumeragiNposJsonAdmissionError::Allocation(error) => error.into(),
        }
    }
}

struct OriginalPolicy {
    completed: Option<((usize, usize), AdmittedSumeragiNposParameters)>,
    budget: AllocationBudget,
}

/// One original immutable signed body and its completed funded policy stage.
///
/// Retries use the inherited cumulative decoder context. They repeat source
/// authentication and every metadata/committee check, but retain the completed
/// policy at its exact signed coordinate. There is no replacement-body, unchecked
/// policy, mutable decoded value or authority-import API.
///
/// The caller still owns native slot checks, enclosing control/source backing,
/// decoder/error scratch and deferred refund scope. This owner admits the policy
/// record and its two quantity magnitudes; it does not fund the returned complete
/// epoch graph or its remaining authentication scratch.
// TODO(S6): retain partial policy decoding and the remaining funded epoch/result
// graphs at their original boundaries without resetting decoder limits.
pub struct OriginalGenesisRead {
    // Drop policy values and their charges before releasing the original body.
    policy: OriginalPolicy,
    genesis: SharedSignedBlock,
}
impl OriginalGenesisRead {
    /// Bind the exact original shared body and its existing allocation pool.
    /// No policy decoding or extra shared body allocation takes place here.
    ///
    /// # Errors
    /// Rejects a pool that does not own the original shared signed body.
    pub fn new(
        genesis: SharedSignedBlock,
        budget: &AllocationBudget,
    ) -> Result<Self, OriginalGenesisReadError> {
        if !genesis.belongs_to(budget) {
            return Err(OriginalGenesisReadError::ForeignPool);
        }
        Ok(Self {
            policy: OriginalPolicy {
                completed: None,
                budget: budget.clone(),
            },
            genesis,
        })
    }

    /// Borrow the immutable original; this projection grants no authentication.
    #[must_use]
    pub fn genesis(&self) -> &SharedSignedBlock {
        &self.genesis
    }

    /// Run the sole canonical authentication, retaining only completed policy work.
    ///
    /// # Errors
    /// Preserves original canonical validation, cumulative decoder and pool refusal.
    pub fn authenticate(&mut self) -> Result<AuthenticatedGenesis, OriginalGenesisReadError> {
        super::authenticate_with_policy(&self.genesis, None, &mut self.policy)
    }
}
impl core::fmt::Debug for OriginalGenesisRead {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OriginalGenesisRead")
            .field("genesis", &self.genesis.hash())
            .field(
                "completed_policy",
                &self
                    .policy
                    .completed
                    .as_ref()
                    .map(|(coordinate, _)| coordinate),
            )
            .finish_non_exhaustive()
    }
}
impl PolicySource for OriginalPolicy {
    type Error = OriginalGenesisReadError;

    fn read(
        &mut self,
        custom: &CustomParameter,
        coordinate: (usize, usize),
    ) -> Result<(), Self::Error> {
        #[cfg(not(all(test, sumeragi_model_mutation = "DM15")))]
        if let Some((original, _)) = &self.completed
            && *original == coordinate
        {
            return Ok(());
        }
        let parameters =
            AdmittedSumeragiNposParameters::from_custom_parameter(custom, &self.budget)?
                .ok_or("invalid signed genesis NPoS parameters")?;
        if self.completed.is_none() {
            self.completed = Some((coordinate, parameters));
        }
        // A later duplicate must decode and validate fully before the canonical
        // duplicate-authority verdict. Its temporary owner retires in caller scope.
        Ok(())
    }

    fn parameters(&self) -> Option<&SumeragiNposParameters> {
        self.completed
            .as_ref()
            .map(|(_, parameters)| parameters.get())
    }
}

#[cfg(test)]
mod tests;
