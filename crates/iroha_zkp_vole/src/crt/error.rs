//! The error type of the CRT table code.

use thiserror::Error;

use crate::field::FieldError;

/// Errors of the CRT table construction, of the table accessors and of the codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CrtError {
    /// The `(lambda, tau, w_grind)` triple is outside what the construction supports.
    #[error("unsupported CRT parameters lambda = {lambda}, tau = {tau}, w_grind = {w_grind}")]
    UnsupportedParameters {
        /// Security parameter.
        lambda: u32,
        /// Number of small-VOLE instances.
        tau: u32,
        /// Number of grinding bits.
        w_grind: u32,
    },
    /// No embedded table set belongs to a parameter row: its `(lambda, tau, w_grind)`
    /// is not one of the eight standard profiles, or its `n_mult` is not the gate
    /// count of that profile's tables.
    #[error(
        "no embedded CRT tables for lambda = {lambda}, tau = {tau}, w_grind = {w_grind}, \
         n_mult = {n_mult}"
    )]
    NoEmbeddedTables {
        /// Security parameter of the row.
        lambda: usize,
        /// Number of small-VOLE instances of the row.
        tau: usize,
        /// Number of grinding bits of the row.
        w_grind: usize,
        /// Number of multiplication gates of the row.
        n_mult: usize,
    },
    /// The enumeration of irreducible polynomials failed.
    #[error("irreducible polynomials: {0}")]
    Field(#[from] FieldError),
    /// A place returned a different number of gate-mask rows than evaluation rows.
    ///
    /// The reference construction appends both lists in full, so a mismatch would
    /// misalign every later residue coordinate; it is never truncated here.
    #[error("a place returned {mask_rows} gate-mask rows for {evaluation_rows} evaluation rows")]
    PlaceRowMismatch {
        /// Rows of gate masks the place returned.
        mask_rows: usize,
        /// Rows of evaluation forms the place returned.
        evaluation_rows: usize,
    },
    /// A linear system that the construction inverts is not square, so its inverse
    /// (and with it the tables) would depend on the pivot rule.
    #[error("evaluation matrix is {rows} x {columns}, expected square")]
    NotSquare {
        /// Number of equations.
        rows: usize,
        /// Number of unknowns.
        columns: usize,
    },
    /// A matrix that must be invertible has no pivot in a column.
    #[error("no pivot in column {column}")]
    Singular {
        /// First column without a pivot.
        column: usize,
    },
    /// No set of places covers the required number of residue coordinates.
    #[error("no set of places covers {target} coordinates")]
    NoPortfolio {
        /// Number of coordinates to cover.
        target: usize,
    },
    /// A polynomial has no inverse modulo another.
    #[error("polynomial is not invertible for the modulus")]
    NotInvertible,
    /// A polynomial division by zero was requested.
    #[error("polynomial division by zero")]
    DivisionByZero,
    /// A step of the construction met a value outside its domain.
    #[error("table construction failed: {what}")]
    Construction {
        /// The step that failed.
        what: &'static str,
    },
    /// A buffer, table or list does not have the required size.
    #[error("{what}: expected {expected}, got {actual}")]
    Shape {
        /// What was measured.
        what: &'static str,
        /// Required size.
        expected: usize,
        /// Supplied size.
        actual: usize,
    },
    /// A value is well-formed in size but not the canonical encoding.
    #[error("not canonical: {what}")]
    NonCanonical {
        /// The offending part.
        what: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    #[test]
    fn every_variant_displays() {
        let field = FieldError::UnsupportedDegree { degree: 0, max: 16 };
        let all = [
            CrtError::UnsupportedParameters {
                lambda: 1,
                tau: 2,
                w_grind: 3,
            },
            CrtError::NoEmbeddedTables {
                lambda: 128,
                tau: 12,
                w_grind: 7,
                n_mult: 312,
            },
            CrtError::Field(field),
            CrtError::PlaceRowMismatch {
                mask_rows: 3,
                evaluation_rows: 2,
            },
            CrtError::NotSquare {
                rows: 3,
                columns: 2,
            },
            CrtError::Singular { column: 1 },
            CrtError::NoPortfolio { target: 9 },
            CrtError::NotInvertible,
            CrtError::DivisionByZero,
            CrtError::Construction { what: "step" },
            CrtError::Shape {
                what: "words",
                expected: 4,
                actual: 5,
            },
            CrtError::NonCanonical { what: "padding" },
        ];
        for error in all {
            assert!(!error.to_string().is_empty());
        }
        assert!(
            CrtError::NoEmbeddedTables {
                lambda: 128,
                tau: 12,
                w_grind: 7,
                n_mult: 312,
            }
            .to_string()
            .ends_with("w_grind = 7, n_mult = 312")
        );
        assert!(
            CrtError::NotSquare {
                rows: 3,
                columns: 2
            }
            .to_string()
            .contains("3 x 2")
        );
    }

    #[test]
    fn field_errors_convert_and_chain() {
        let field = FieldError::UnsupportedDegree { degree: 0, max: 16 };
        let error = CrtError::from(field);
        assert_eq!(error, CrtError::Field(field));
        assert!(error.source().is_some());
        assert!(CrtError::NotInvertible.source().is_none());
    }
}
