//! The eight standard table sets, embedded as statics, and the lookup from a
//! parameter row to its set.
//!
//! The files under `src/crt/generated/` are written by
//! [`write_rust_source`](super::codec::write_rust_source) from the output of
//! [`generate_profile`](super::generator::generate_profile) and are never edited by
//! hand. To rewrite them run
//! `cargo test -p iroha_zkp_vole --test conformance_crt -- --ignored`; the ordinary
//! run of that test file regenerates every set and compares it with the embedded
//! one word for word, with the file on disk, and with pinned SHAKE256 digests.
//!
//! Each static is built in a constant context from the generated arrays, so reading
//! a set costs nothing at run time and cannot fail: there is no lazily initialised
//! global and no start-up computation.
//!
//! The construction of the tables follows the FAEST v3.0.2 reference table
//! generator (MIT licence); the upstream licence text is
//! `src/crt/generated/LICENSE.faest-ref`.

use super::{
    error::CrtError,
    tables::{CrtTables, Profile, TableWords},
};
use crate::params::VoleParams;

/// Generated tables of profile `128s`.
#[rustfmt::skip]
mod faest_128s_tables;
/// Generated tables of profile `128f`.
#[rustfmt::skip]
mod faest_128f_tables;
/// Generated tables of profile `192s`.
#[rustfmt::skip]
mod faest_192s_tables;
/// Generated tables of profile `192f`.
#[rustfmt::skip]
mod faest_192f_tables;
/// Generated tables of profile `256s`.
#[rustfmt::skip]
mod faest_256s_tables;
/// Generated tables of profile `256f`.
#[rustfmt::skip]
mod faest_256f_tables;
/// Generated tables of profile `em_192s`.
#[rustfmt::skip]
mod faest_em_192s_tables;
/// Generated tables of profile `em_192f`.
#[rustfmt::skip]
mod faest_em_192f_tables;

/// Build the static table set of one generated module.
macro_rules! embedded {
    ($name:ident, $module:ident) => {
        static $name: CrtTables<'static> = {
            assert!($module::N_DELTA == $module::LAMBDA - $module::W_GRIND);
            CrtTables::from_static(TableWords {
                lambda: $module::LAMBDA,
                tau: $module::TAU,
                w_grind: $module::W_GRIND,
                n_mult: $module::N_MULT,
                tree_moduli: &$module::TREE_MODULI,
                m_tree: &$module::M_TREE,
                f: &$module::F,
                g: &$module::G,
                w_tree: &$module::W_TREE,
                w_gate: &$module::W_GATE,
                w_crt: &$module::W_CRT,
            })
        };
    };
}

embedded!(FAEST_128S, faest_128s_tables);
embedded!(FAEST_128F, faest_128f_tables);
embedded!(FAEST_192S, faest_192s_tables);
embedded!(FAEST_192F, faest_192f_tables);
embedded!(FAEST_256S, faest_256s_tables);
embedded!(FAEST_256F, faest_256f_tables);
embedded!(FAEST_EM_192S, faest_em_192s_tables);
embedded!(FAEST_EM_192F, faest_em_192f_tables);

/// File name, in `src/crt/generated/`, of the generated source of a profile.
pub fn file_name(profile: Profile) -> String {
    format!("faest_{}_tables.rs", profile.name())
}

/// The embedded table set of a standard profile.
pub const fn tables(profile: Profile) -> &'static CrtTables<'static> {
    match profile {
        Profile::Faest128s => &FAEST_128S,
        Profile::Faest128f => &FAEST_128F,
        Profile::Faest192s => &FAEST_192S,
        Profile::Faest192f => &FAEST_192F,
        Profile::Faest256s => &FAEST_256S,
        Profile::Faest256f => &FAEST_256F,
        Profile::FaestEm192s => &FAEST_EM_192S,
        Profile::FaestEm192f => &FAEST_EM_192F,
    }
}

/// The embedded table set a parameter row uses; see [`Profile::of`] for the rule
/// and for the FAEST-EM rows that share a set.
///
/// A row without an embedded set can still be served by an explicit call of
/// [`generate`](super::generator::generate), at the caller's cost.
///
/// # Errors
/// [`CrtError::NoEmbeddedTables`] unless `(lambda, tau, w_grind)` of the row is one
/// of the eight standard profiles and the row's `n_mult` is the gate count of that
/// profile's tables.
pub fn tables_for(params: &VoleParams) -> Result<&'static CrtTables<'static>, CrtError> {
    Profile::of(params)
        .map(tables)
        .ok_or_else(|| CrtError::NoEmbeddedTables {
            lambda: params.lambda().bits(),
            tau: params.tau(),
            w_grind: params.w_grind(),
            n_mult: params.n_mult(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{FAEST_PARAMETER_SETS, SecurityLevel};

    #[test]
    fn file_names() {
        assert_eq!(file_name(Profile::Faest128s), "faest_128s_tables.rs");
        assert_eq!(file_name(Profile::FaestEm192f), "faest_em_192f_tables.rs");
    }

    /// The constant construction skips the consistency checks; here every embedded
    /// set passes them and equals the checked construction over the same words.
    #[test]
    fn every_embedded_set_passes_the_full_checks() {
        for profile in Profile::ALL {
            let embedded = tables(profile);
            let checked = CrtTables::from_words(&embedded.as_words()).expect("consistent tables");
            assert_eq!(&checked, embedded, "{}", profile.name());
            assert_eq!(embedded.profile(), Some(profile));
            let (lambda, tau, w_grind) = profile.parameters();
            assert_eq!(
                (embedded.lambda(), embedded.tau(), embedded.w_grind()),
                (lambda, tau, w_grind)
            );
            assert_eq!(embedded.n_mult(), profile.n_mult(), "{}", profile.name());
        }
    }

    #[test]
    fn the_twelve_standard_rows_find_their_tables() {
        let expected = [
            Profile::Faest128s,
            Profile::Faest128f,
            Profile::Faest192s,
            Profile::Faest192f,
            Profile::Faest256s,
            Profile::Faest256f,
            Profile::Faest128s,
            Profile::Faest128f,
            Profile::FaestEm192s,
            Profile::FaestEm192f,
            Profile::Faest256s,
            Profile::Faest256f,
        ];
        for (set, profile) in FAEST_PARAMETER_SETS.iter().zip(expected) {
            let found = tables_for(set.vole()).expect("standard row");
            assert!(std::ptr::eq(found, tables(profile)), "{}", set.name());
            assert_eq!(
                usize::try_from(found.n_delta()).ok(),
                Some(set.vole().n_delta())
            );
        }
    }

    #[test]
    fn a_row_without_tables_is_a_typed_error() {
        let row = VoleParams::new(SecurityLevel::L128, 12, 7, 102, 3, 7, 312).expect("valid row");
        assert_eq!(
            tables_for(&row),
            Err(CrtError::NoEmbeddedTables {
                lambda: 128,
                tau: 12,
                w_grind: 7,
                n_mult: 312
            })
        );
        let row = VoleParams::new(SecurityLevel::L128, 11, 7, 102, 3, 7, 313).expect("valid row");
        assert_eq!(
            tables_for(&row),
            Err(CrtError::NoEmbeddedTables {
                lambda: 128,
                tau: 11,
                w_grind: 7,
                n_mult: 313
            })
        );
    }
}
