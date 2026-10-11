//! Owned secret field buffers, wiped on every exit including cancellation.

use iroha_pasta::PastaField;

/// A polynomial whose allocation is wiped before release.
#[derive(Debug)]
pub struct SecretPolynomial<F: PastaField>(Vec<F>);

impl<F: PastaField> SecretPolynomial<F> {
    /// Takes ownership without copying coefficients.
    pub fn new(values: Vec<F>) -> Self {
        Self(values)
    }

    /// Moves coefficients to another owner that takes responsibility for wiping.
    pub fn into_vec(mut self) -> Vec<F> {
        core::mem::take(&mut self.0)
    }

    /// Wipes discarded coefficients before reducing the live length.
    pub fn truncate(&mut self, length: usize) {
        if length < self.0.len() {
            self.0[length..]
                .iter_mut()
                .for_each(crate::secret::wipe_one);
            self.0.truncate(length);
        }
    }
}
impl<F: PastaField> core::ops::Deref for SecretPolynomial<F> {
    type Target = Vec<F>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<F: PastaField> core::ops::DerefMut for SecretPolynomial<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl<F: PastaField> Drop for SecretPolynomial<F> {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(crate::secret::wipe_one);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_pasta::Fp;
    #[test]
    fn ownership_moves_without_copy_and_truncation_keeps_capacity() {
        let values = vec![Fp::from(7); 16];
        let pointer = values.as_ptr();
        let mut secret = SecretPolynomial::new(values);
        secret.truncate(8);
        assert_eq!(secret.len(), 8);
        assert_eq!(secret.capacity(), 16);
        secret.truncate(32);
        let result = secret.into_vec();
        assert_eq!(result.as_ptr(), pointer);
        assert_eq!(result, vec![Fp::from(7); 8]);
    }
}

/// Field columns retained across kernel phases.
#[derive(Clone, Debug)]
pub struct SecretColumns<F: PastaField>(Vec<Vec<F>>);
impl<F: PastaField> SecretColumns<F> {
    pub fn new(values: Vec<Vec<F>>) -> Self {
        Self(values)
    }
    pub fn into_vec(mut self) -> Vec<Vec<F>> {
        core::mem::take(&mut self.0)
    }
}
impl<F: PastaField> core::ops::Deref for SecretColumns<F> {
    type Target = Vec<Vec<F>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<F: PastaField> core::ops::DerefMut for SecretColumns<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl<F: PastaField> Drop for SecretColumns<F> {
    fn drop(&mut self) {
        self.0
            .iter_mut()
            .flatten()
            .for_each(crate::secret::wipe_one);
    }
}

/// Pending compressed lookup inputs and tables.
pub struct SecretLookupColumns<F: PastaField>(Vec<(Vec<F>, Vec<F>)>);
impl<F: PastaField> SecretLookupColumns<F> {
    pub fn new(values: Vec<(Vec<F>, Vec<F>)>) -> Self {
        Self(values)
    }
}
impl<F: PastaField> core::ops::Deref for SecretLookupColumns<F> {
    type Target = Vec<(Vec<F>, Vec<F>)>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<F: PastaField> core::ops::DerefMut for SecretLookupColumns<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl<F: PastaField> Drop for SecretLookupColumns<F> {
    fn drop(&mut self) {
        for (input, table) in &mut self.0 {
            input
                .iter_mut()
                .chain(table)
                .for_each(crate::secret::wipe_one);
        }
    }
}

/// Wipe one sealed field value without an additional trait dependency.
pub fn wipe_one<F: PastaField>(value: &mut F) {
    value.zeroize();
}
