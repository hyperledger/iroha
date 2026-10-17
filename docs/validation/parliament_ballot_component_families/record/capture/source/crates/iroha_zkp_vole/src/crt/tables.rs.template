//! A set of CRT tables, the eight standard profiles, and checked access.
//!
//! For parameters `(lambda, tau, w_grind)` with `n_delta = lambda - w_grind` and
//! `n_mult` multiplication gates a set consists of:
//!
//! | table | rows | row width | row `r`, bit `c` |
//! |---|---|---|---|
//! | `F` | `n_mult` | `lambda` | gate `r` reads bit `c` of the field element |
//! | `G` | `n_mult` | `n_delta` | gate `r` reads residue bit `c` of the challenge |
//! | `W_TREE` | `lambda` | `n_delta` | output bit `r` takes tree residue coordinate `c` |
//! | `W_GATE` | `lambda` | `n_mult` | output bit `r` takes gate `c` |
//! | `W_CRT` | `lambda` | `n_delta` | bit `r` of the CRT lift takes residue bit `c` |
//!
//! together with the `tau` tree moduli (each the full polynomial with its leading
//! bit, bit `i` being the coefficient of `x^i`) and their product `M_TREE` of
//! `n_delta + 1` bits. Residue bit `b` of tree instance `i` is coordinate
//! `start_i + b`, where `start_i` is the sum of the degrees of the earlier moduli.
//! All of it is public data.

use std::borrow::Cow;

use super::{bits::Bits, bits::index, error::CrtError, gf2poly, matrix::BitMatrix};
use crate::params::VoleParams;

/// The eight table sets of FAEST v3.0. FAEST-EM-128s/f and FAEST-EM-256s/f use the
/// sets of FAEST-128s/f and FAEST-256s/f.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Profile {
    /// FAEST-128s and FAEST-EM-128s: `(128, 11, 7)`.
    Faest128s,
    /// FAEST-128f and FAEST-EM-128f: `(128, 17, 8)`.
    Faest128f,
    /// FAEST-192s: `(192, 16, 12)`.
    Faest192s,
    /// FAEST-192f: `(192, 24, 8)`.
    Faest192f,
    /// FAEST-256s and FAEST-EM-256s: `(256, 22, 6)`.
    Faest256s,
    /// FAEST-256f and FAEST-EM-256f: `(256, 33, 8)`.
    Faest256f,
    /// FAEST-EM-192s: `(192, 16, 8)`.
    FaestEm192s,
    /// FAEST-EM-192f: `(192, 25, 8)`.
    FaestEm192f,
}

impl Profile {
    /// Every profile, in the order of the reference implementation.
    pub const ALL: [Self; 8] = [
        Self::Faest128s,
        Self::Faest128f,
        Self::Faest192s,
        Self::Faest192f,
        Self::Faest256s,
        Self::Faest256f,
        Self::FaestEm192s,
        Self::FaestEm192f,
    ];

    /// The triple `(lambda, tau, w_grind)` of the profile.
    pub const fn parameters(self) -> (u32, u32, u32) {
        match self {
            Self::Faest128s => (128, 11, 7),
            Self::Faest128f => (128, 17, 8),
            Self::Faest192s => (192, 16, 12),
            Self::Faest192f => (192, 24, 8),
            Self::Faest256s => (256, 22, 6),
            Self::Faest256f => (256, 33, 8),
            Self::FaestEm192s => (192, 16, 8),
            Self::FaestEm192f => (192, 25, 8),
        }
    }

    /// The short name of the profile, as in the reference table files.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Faest128s => "128s",
            Self::Faest128f => "128f",
            Self::Faest192s => "192s",
            Self::Faest192f => "192f",
            Self::Faest256s => "256s",
            Self::Faest256f => "256f",
            Self::FaestEm192s => "em_192s",
            Self::FaestEm192f => "em_192f",
        }
    }

    /// Number of multiplication gates `n_mult` of the profile.
    pub const fn n_mult(self) -> u32 {
        match self {
            Self::Faest128s | Self::Faest128f => 312,
            Self::Faest192s | Self::Faest192f | Self::FaestEm192s | Self::FaestEm192f => 504,
            Self::Faest256s => 696,
            Self::Faest256f => 704,
        }
    }

    /// The profile whose tables a parameter row uses: the one with the row's
    /// `(lambda, tau, w_grind)`, provided the row has the gate count `n_mult` of
    /// that profile's tables.
    ///
    /// The four FAEST-EM rows at 128 and 256 bits share the triples, and so the
    /// tables, of the FAEST rows of the same name; FAEST-EM-192s and FAEST-EM-192f
    /// have profiles of their own.
    pub fn of(params: &VoleParams) -> Option<Self> {
        let narrow = |value: usize| u32::try_from(value).ok();
        let lambda = narrow(params.lambda().bits())?;
        let profile =
            Self::from_parameters(lambda, narrow(params.tau())?, narrow(params.w_grind())?)?;
        (narrow(params.n_mult()) == Some(profile.n_mult())).then_some(profile)
    }

    /// The profile with the given `(lambda, tau, w_grind)`, if it is a standard one.
    pub fn from_parameters(lambda: u32, tau: u32, w_grind: u32) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|profile| profile.parameters() == (lambda, tau, w_grind))
    }
}

/// The raw words of a table set, for example the items of a generated source file.
/// [`CrtTables::from_words`] checks them and borrows them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableWords<'a> {
    /// Security parameter `lambda`.
    pub lambda: u32,
    /// Number of small-VOLE instances `tau`.
    pub tau: u32,
    /// Number of grinding bits `w_grind`.
    pub w_grind: u32,
    /// Number of multiplication gates `n_mult`.
    pub n_mult: u32,
    /// The `tau` tree moduli.
    pub tree_moduli: &'a [u16],
    /// `M_TREE` in `ceil((n_delta + 1) / 64)` words.
    pub m_tree: &'a [u64],
    /// Table `F`.
    pub f: &'a [u64],
    /// Table `G`.
    pub g: &'a [u64],
    /// Table `W_TREE`.
    pub w_tree: &'a [u64],
    /// Table `W_GATE`.
    pub w_gate: &'a [u64],
    /// Table `W_CRT`.
    pub w_crt: &'a [u64],
}

/// A checked set of CRT tables; see the module documentation for the layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrtTables<'a> {
    lambda: u32,
    tau: u32,
    w_grind: u32,
    n_mult: u32,
    tree_moduli: Cow<'a, [u16]>,
    m_tree: Cow<'a, [u64]>,
    f: BitMatrix<'a>,
    g: BitMatrix<'a>,
    w_tree: BitMatrix<'a>,
    w_gate: BitMatrix<'a>,
    w_crt: BitMatrix<'a>,
}

/// Degree of a tree modulus; zero for the constants, which are not moduli.
fn modulus_degree(modulus: u16) -> u32 {
    15u32.saturating_sub(modulus.leading_zeros())
}

impl CrtTables<'static> {
    /// The table set of an embedded source file, built in a constant context.
    ///
    /// Only the parameter range and the word counts are checked, and a violation
    /// fails the build; the full checks of [`CrtTables::from_words`] are applied to
    /// every embedded set by the tests of [`super::generated`], which compare the
    /// two constructions.
    pub(super) const fn from_static(words: TableWords<'static>) -> Self {
        assert!(words.w_grind != 0 && words.w_grind < words.lambda && words.tau != 0);
        let lambda = words.lambda as usize;
        let n_delta = (words.lambda - words.w_grind) as usize;
        let n_mult = words.n_mult as usize;
        assert!(words.tree_moduli.len() == words.tau as usize);
        assert!(words.m_tree.len() == (n_delta + 1).div_ceil(64));
        Self {
            lambda: words.lambda,
            tau: words.tau,
            w_grind: words.w_grind,
            n_mult: words.n_mult,
            tree_moduli: Cow::Borrowed(words.tree_moduli),
            m_tree: Cow::Borrowed(words.m_tree),
            f: BitMatrix::from_static(n_mult, lambda, words.f),
            g: BitMatrix::from_static(n_mult, n_delta, words.g),
            w_tree: BitMatrix::from_static(lambda, n_delta, words.w_tree),
            w_gate: BitMatrix::from_static(lambda, n_mult, words.w_gate),
            w_crt: BitMatrix::from_static(lambda, n_delta, words.w_crt),
        }
    }
}

impl<'a> CrtTables<'a> {
    /// Check the shapes and the internal consistency of `words` and borrow them.
    ///
    /// The checks are: `0 < w_grind < lambda`; `tau` moduli of degree at least one
    /// whose degrees sum to `n_delta = lambda - w_grind`; `M_TREE` is their product;
    /// the five tables have the dimensions of the module documentation and no bit
    /// at or above their row width; and the rows of `W_CRT` at or above `n_delta`
    /// are zero. The cost is linear in the size of the tables.
    ///
    /// # Errors
    /// [`CrtError::Shape`] for a wrong size or count, [`CrtError::NonCanonical`]
    /// for a value that is inconsistent, and [`CrtError::UnsupportedParameters`]
    /// for parameters out of range.
    pub fn from_words(words: &TableWords<'a>) -> Result<Self, CrtError> {
        let unsupported = CrtError::UnsupportedParameters {
            lambda: words.lambda,
            tau: words.tau,
            w_grind: words.w_grind,
        };
        if words.w_grind == 0 || words.w_grind >= words.lambda || words.tau == 0 {
            return Err(unsupported);
        }
        let lambda = index(words.lambda);
        let n_delta = index(words.lambda - words.w_grind);
        let n_mult = index(words.n_mult);
        if words.tree_moduli.len() != index(words.tau) {
            return Err(CrtError::Shape {
                what: "tree moduli",
                expected: index(words.tau),
                actual: words.tree_moduli.len(),
            });
        }
        // The degrees are summed before anything is multiplied, so the product
        // below never exceeds degree `n_delta < lambda` whatever the input is.
        let mut degrees = 0usize;
        for modulus in words.tree_moduli {
            if *modulus < 2 {
                return Err(CrtError::NonCanonical {
                    what: "a tree modulus of degree zero",
                });
            }
            degrees = degrees.saturating_add(index(modulus_degree(*modulus)));
        }
        if degrees != n_delta {
            return Err(CrtError::Shape {
                what: "sum of the tree modulus degrees",
                expected: n_delta,
                actual: degrees,
            });
        }
        let mut product = Bits::from_u64(1);
        for modulus in words.tree_moduli {
            product = gf2poly::mul(&product, &Bits::from_u64(u64::from(*modulus)));
        }
        let m_tree_words = (n_delta + 1).div_ceil(64);
        if words.m_tree.len() != m_tree_words {
            return Err(CrtError::Shape {
                what: "M_TREE words",
                expected: m_tree_words,
                actual: words.m_tree.len(),
            });
        }
        if product.to_words(m_tree_words).as_deref() != Some(words.m_tree) {
            return Err(CrtError::NonCanonical {
                what: "M_TREE is not the product of the tree moduli",
            });
        }
        let w_crt = BitMatrix::borrowed(lambda, n_delta, words.w_crt)?;
        let tail_is_zero = (n_delta..lambda).all(|row| {
            w_crt
                .row(row)
                .is_some_and(|line| line.iter().all(|word| *word == 0))
        });
        if !tail_is_zero {
            return Err(CrtError::NonCanonical {
                what: "a row of W_CRT at or above n_delta is not zero",
            });
        }
        Ok(Self {
            lambda: words.lambda,
            tau: words.tau,
            w_grind: words.w_grind,
            n_mult: words.n_mult,
            tree_moduli: Cow::Borrowed(words.tree_moduli),
            m_tree: Cow::Borrowed(words.m_tree),
            f: BitMatrix::borrowed(n_mult, lambda, words.f)?,
            g: BitMatrix::borrowed(n_mult, n_delta, words.g)?,
            w_tree: BitMatrix::borrowed(lambda, n_delta, words.w_tree)?,
            w_gate: BitMatrix::borrowed(lambda, n_mult, words.w_gate)?,
            w_crt,
        })
    }

    /// The same set owning all its words.
    pub fn into_owned(self) -> CrtTables<'static> {
        CrtTables {
            lambda: self.lambda,
            tau: self.tau,
            w_grind: self.w_grind,
            n_mult: self.n_mult,
            tree_moduli: Cow::Owned(self.tree_moduli.into_owned()),
            m_tree: Cow::Owned(self.m_tree.into_owned()),
            f: self.f.into_owned(),
            g: self.g.into_owned(),
            w_tree: self.w_tree.into_owned(),
            w_gate: self.w_gate.into_owned(),
            w_crt: self.w_crt.into_owned(),
        }
    }

    /// The raw words of the set.
    pub fn as_words(&self) -> TableWords<'_> {
        TableWords {
            lambda: self.lambda,
            tau: self.tau,
            w_grind: self.w_grind,
            n_mult: self.n_mult,
            tree_moduli: &self.tree_moduli,
            m_tree: &self.m_tree,
            f: self.f.as_words(),
            g: self.g.as_words(),
            w_tree: self.w_tree.as_words(),
            w_gate: self.w_gate.as_words(),
            w_crt: self.w_crt.as_words(),
        }
    }

    /// Security parameter `lambda`.
    pub const fn lambda(&self) -> u32 {
        self.lambda
    }

    /// Number of small-VOLE instances `tau`.
    pub const fn tau(&self) -> u32 {
        self.tau
    }

    /// Number of grinding bits `w_grind`.
    pub const fn w_grind(&self) -> u32 {
        self.w_grind
    }

    /// Challenge length `n_delta = lambda - w_grind`.
    pub const fn n_delta(&self) -> u32 {
        self.lambda - self.w_grind
    }

    /// Number of multiplication gates `n_mult`.
    pub const fn n_mult(&self) -> u32 {
        self.n_mult
    }

    /// The standard profile these parameters belong to, if any.
    pub fn profile(&self) -> Option<Profile> {
        Profile::from_parameters(self.lambda, self.tau, self.w_grind)
    }

    /// The `tau` tree moduli in instance order.
    pub fn tree_moduli(&self) -> &[u16] {
        &self.tree_moduli
    }

    /// The modulus of tree instance `instance`, or `None` if there is none.
    pub fn tree_modulus(&self, instance: usize) -> Option<u16> {
        self.tree_moduli.get(instance).copied()
    }

    /// The degree of the modulus of tree instance `instance`: the bit length of its
    /// small-VOLE challenge.
    pub fn tree_degree(&self, instance: usize) -> Option<u32> {
        self.tree_modulus(instance).map(modulus_degree)
    }

    /// The first residue coordinate of tree instance `instance`: the sum of the
    /// degrees of the earlier moduli.
    pub fn residue_offset(&self, instance: usize) -> Option<u32> {
        self.tree_moduli.get(..instance).and_then(|earlier| {
            (instance < self.tree_moduli.len())
                .then(|| earlier.iter().map(|modulus| modulus_degree(*modulus)).sum())
        })
    }

    /// `M_TREE`, the product of the tree moduli, in little-endian words.
    pub fn m_tree(&self) -> &[u64] {
        &self.m_tree
    }

    /// Table `F`: `n_mult x lambda`.
    pub const fn f(&self) -> &BitMatrix<'a> {
        &self.f
    }

    /// Table `G`: `n_mult x n_delta`.
    pub const fn g(&self) -> &BitMatrix<'a> {
        &self.g
    }

    /// Table `W_TREE`: `lambda x n_delta`.
    pub const fn w_tree(&self) -> &BitMatrix<'a> {
        &self.w_tree
    }

    /// Table `W_GATE`: `lambda x n_mult`.
    pub const fn w_gate(&self) -> &BitMatrix<'a> {
        &self.w_gate
    }

    /// Table `W_CRT`: `lambda x n_delta`.
    pub const fn w_crt(&self) -> &BitMatrix<'a> {
        &self.w_crt
    }
}

#[cfg(test)]
pub mod testing {
    //! A small consistent table set for the unit tests of this directory.

    use super::*;

    /// Words of a toy set with `lambda = 4`, `tau = 2`, `w_grind = 1`, `n_mult = 2`
    /// and the moduli `x` and `x^2 + x + 1`.
    pub const TOY: TableWords<'static> = TableWords {
        lambda: 4,
        tau: 2,
        w_grind: 1,
        n_mult: 2,
        tree_moduli: &[0b10, 0b111],
        m_tree: &[0b1110],
        f: &[0b1001, 0b0110],
        g: &[0b101, 0b011],
        w_tree: &[0b001, 0b010, 0b100, 0b111],
        w_gate: &[0b01, 0b10, 0b11, 0b00],
        w_crt: &[0b110, 0b011, 0b101, 0],
    };
}

#[cfg(test)]
mod tests {
    use super::{testing::TOY, *};

    #[test]
    fn profiles_and_their_parameters() {
        assert_eq!(Profile::ALL.len(), 8);
        let names: Vec<&str> = Profile::ALL.iter().map(|profile| profile.name()).collect();
        assert_eq!(
            names,
            [
                "128s", "128f", "192s", "192f", "256s", "256f", "em_192s", "em_192f"
            ]
        );
        let gates: Vec<u32> = Profile::ALL
            .iter()
            .map(|profile| profile.n_mult())
            .collect();
        assert_eq!(gates, [312, 312, 504, 504, 696, 704, 504, 504]);
        let n_delta: Vec<u32> = Profile::ALL
            .iter()
            .map(|profile| {
                let (lambda, _, w_grind) = profile.parameters();
                lambda - w_grind
            })
            .collect();
        assert_eq!(n_delta, [121, 120, 180, 184, 250, 248, 184, 184]);
        for profile in Profile::ALL {
            let (lambda, tau, w_grind) = profile.parameters();
            assert_eq!(
                Profile::from_parameters(lambda, tau, w_grind),
                Some(profile)
            );
        }
        assert_eq!(Profile::from_parameters(128, 11, 8), None);
        assert_eq!(
            Profile::from_parameters(192, 16, 8),
            Some(Profile::FaestEm192s)
        );
    }

    #[test]
    fn profiles_of_parameter_rows() {
        use crate::params::{
            FAEST_128S, FAEST_256F, FAEST_EM_128F, FAEST_EM_192F, FAEST_EM_192S, FAEST_EM_256S,
            SecurityLevel,
        };

        assert_eq!(Profile::of(FAEST_128S.vole()), Some(Profile::Faest128s));
        assert_eq!(Profile::of(FAEST_256F.vole()), Some(Profile::Faest256f));
        assert_eq!(Profile::of(FAEST_EM_128F.vole()), Some(Profile::Faest128f));
        assert_eq!(
            Profile::of(FAEST_EM_192S.vole()),
            Some(Profile::FaestEm192s)
        );
        assert_eq!(
            Profile::of(FAEST_EM_192F.vole()),
            Some(Profile::FaestEm192f)
        );
        assert_eq!(Profile::of(FAEST_EM_256S.vole()), Some(Profile::Faest256s));
        // A custom row keeps its profile whatever T_open, n_leafcom and d_zk are,
        // and loses it with another gate count or another triple.
        let row = |tau, n_mult| {
            VoleParams::new(SecurityLevel::L256, tau, 8, 300, 2, 9, n_mult).expect("valid row")
        };
        assert_eq!(Profile::of(&row(33, 704)), Some(Profile::Faest256f));
        assert_eq!(Profile::of(&row(33, 696)), None);
        assert_eq!(Profile::of(&row(32, 704)), None);
    }

    #[test]
    fn modulus_degrees() {
        assert_eq!(modulus_degree(0), 0);
        assert_eq!(modulus_degree(1), 0);
        assert_eq!(modulus_degree(0b10), 1);
        assert_eq!(modulus_degree(0x11b), 8);
        assert_eq!(modulus_degree(0x1009), 12);
    }

    #[test]
    fn the_toy_set_is_accepted_and_readable() {
        let tables = CrtTables::from_words(&TOY).expect("consistent");
        assert_eq!((tables.lambda(), tables.tau(), tables.w_grind()), (4, 2, 1));
        assert_eq!((tables.n_delta(), tables.n_mult()), (3, 2));
        assert_eq!(tables.profile(), None);
        assert_eq!(tables.tree_moduli(), &[0b10, 0b111]);
        assert_eq!(tables.tree_modulus(1), Some(0b111));
        assert_eq!(tables.tree_modulus(2), None);
        assert_eq!(tables.tree_degree(0), Some(1));
        assert_eq!(tables.tree_degree(1), Some(2));
        assert_eq!(tables.tree_degree(2), None);
        assert_eq!(tables.residue_offset(0), Some(0));
        assert_eq!(tables.residue_offset(1), Some(1));
        assert_eq!(tables.residue_offset(2), None);
        assert_eq!(tables.m_tree(), &[0b1110]);
        assert_eq!((tables.f().rows(), tables.f().cols()), (2, 4));
        assert_eq!((tables.g().rows(), tables.g().cols()), (2, 3));
        assert_eq!((tables.w_tree().rows(), tables.w_tree().cols()), (4, 3));
        assert_eq!((tables.w_gate().rows(), tables.w_gate().cols()), (4, 2));
        assert_eq!((tables.w_crt().rows(), tables.w_crt().cols()), (4, 3));
        assert_eq!(tables.as_words(), TOY);
        let owned = tables.clone().into_owned();
        assert_eq!(owned, tables);
        assert_eq!(owned.as_words(), TOY);
    }

    #[test]
    fn the_constant_construction_is_the_checked_one() {
        const FIXED: CrtTables<'static> = CrtTables::from_static(TOY);
        assert_eq!(Ok(FIXED), CrtTables::from_words(&TOY));
    }

    /// A hostile modulus list is refused by its degree sum before any product
    /// is formed; multiplying a million moduli first would not finish in a test.
    #[test]
    fn an_oversized_modulus_list_is_rejected_before_multiplying() {
        const COUNT: usize = 1_000_000;
        let moduli = vec![0b10u16; COUNT];
        let outcome = CrtTables::from_words(&TableWords {
            tau: 1_000_000,
            tree_moduli: &moduli,
            ..TOY
        });
        assert_eq!(
            outcome,
            Err(CrtError::Shape {
                what: "sum of the tree modulus degrees",
                expected: 3,
                actual: COUNT,
            })
        );
        let short = CrtTables::from_words(&TableWords {
            tau: 2,
            tree_moduli: &[0b10, 0b11],
            ..TOY
        });
        assert_eq!(
            short,
            Err(CrtError::Shape {
                what: "sum of the tree modulus degrees",
                expected: 3,
                actual: 2,
            })
        );
    }

    #[test]
    fn inconsistent_words_are_rejected() {
        let reject = |words: TableWords<'static>| CrtTables::from_words(&words).is_err();
        assert!(reject(TableWords { w_grind: 0, ..TOY }));
        assert!(reject(TableWords { w_grind: 4, ..TOY }));
        assert!(reject(TableWords { tau: 0, ..TOY }));
        assert!(reject(TableWords { tau: 3, ..TOY }));
        assert!(reject(TableWords { n_mult: 3, ..TOY }));
        assert!(reject(TableWords { n_mult: 0, ..TOY }));
        assert!(reject(TableWords { lambda: 5, ..TOY }));
        assert!(reject(TableWords {
            tree_moduli: &[0b1, 0b111],
            ..TOY
        }));
        assert!(reject(TableWords {
            tree_moduli: &[0b10, 0b11],
            ..TOY
        }));
        assert!(reject(TableWords {
            tree_moduli: &[0b11, 0b111],
            ..TOY
        }));
        assert!(reject(TableWords {
            m_tree: &[0b1110, 0],
            ..TOY
        }));
        assert!(reject(TableWords {
            m_tree: &[0b1111],
            ..TOY
        }));
        assert!(reject(TableWords {
            f: &[0b1_1001, 0b0110],
            ..TOY
        }));
        assert!(reject(TableWords { g: &[0b101], ..TOY }));
        assert!(reject(TableWords {
            w_tree: &[1, 2, 4, 8],
            ..TOY
        }));
        assert!(reject(TableWords {
            w_gate: &[1, 2, 4, 0],
            ..TOY
        }));
        assert_eq!(
            CrtTables::from_words(&TableWords {
                w_crt: &[0b110, 0b011, 0b101, 1],
                ..TOY
            }),
            Err(CrtError::NonCanonical {
                what: "a row of W_CRT at or above n_delta is not zero"
            })
        );
    }
}
