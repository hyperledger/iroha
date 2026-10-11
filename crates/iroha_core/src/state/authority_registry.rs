//! Exhaustive classification of persistent State authority and physical owners.
//!
//! Each owner is destructured without `..` by the same declaration that supplies
//! its registry. A new field or changed field type therefore needs an explicit
//! classification before the crate compiles. Schema names come from Norito's
//! declared identities, never Rust paths inferred at runtime.
//!
//! This is an inventory, not a certificate that a derived index has been checked.
//! Existing reconstruction evidence and missing projection/checker obligations
//! remain distinct. In particular config objects, opaque verifier handles and
//! historical cursors cannot silently become node-local policy.
//!
//! The World state accumulator (`world_projection::WorldStateAccumulator`)
//! commits exactly the canonical World fields declared here, and the execution
//! result `R` binds its root. TODO(S9): supply every required semantic
//! projection and derivation validator for the State-level fields and bind
//! recovery to one predecessor. No row disclosure or proof authority is
//! provided here.

use norito::{NoritoSchema, codec::Encode};

// Borrow concrete original current/undo owners without admitting arbitrary row suppliers.
pub(crate) mod original_images;

mod account_alias_ownership;

mod account_identity_ownership;

pub(in crate::state) mod borrowed_controller_work;

mod grouped_ownership;

/// Fixed bare payload layout for a canonical V1 State leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalLayout {
    /// Norito major version selecting the payload contract.
    pub major: u8,
    /// Norito minor version selecting the payload contract.
    pub minor: u8,
    /// Explicit flags; no ambient thread-local encoder selection is permitted.
    pub flags: u8,
}

/// Canonical payloads use the same explicit V1 compact-length layout.
pub(crate) const V1_LAYOUT: CanonicalLayout = CanonicalLayout {
    major: norito::core::VERSION_MAJOR,
    minor: norito::core::VERSION_MINOR,
    flags: norito::core::default_encode_flags(),
};

/// Codec evidence for one key or value; unresolved projections block cutover.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Schema {
    /// Existing Norito codec with its explicit nominal schema declaration.
    Norito {
        /// Exact declared identity: literal names are borrowed; generic names retain ownership.
        nominal_name: fn() -> std::borrow::Cow<'static, str>,
        /// Explicit payload layout used by the leaf encoder.
        layout: CanonicalLayout,
    },
    /// Existing borrowed semantic encoder excluding materialized runtime caches.
    Semantic {
        /// Explicit schema identity for this projection.
        identity: &'static str,
        /// Source owner that implements the exact projection.
        encoder: &'static str,
        /// Explicit payload layout used by the leaf encoder.
        layout: CanonicalLayout,
    },
    /// A consensus-relevant object still needs a canonical semantic projection.
    Required {
        /// Reserved projection identity; this does not assert an existing codec.
        identity: &'static str,
        /// Concrete implementation obligation before a complete State root.
        obligation: &'static str,
    },
}

/// Resolve the declared type schema only when inspection is requested.
pub(crate) const fn schema<T: Encode + NoritoSchema>() -> Schema {
    Schema::Norito {
        nominal_name: norito::schema::identity::nominal_name::<T>,
        layout: V1_LAYOUT,
    }
}

/// Shape of independent canonical authority; nested owners remain exhaustive.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Canonical {
    /// Keyed table. The Rust owner iterates in its own `Ord`; the keyed State commitment
    /// orders entries by canonical key bytes instead (`specs/sumeragi.md` §16.1, §16.2).
    Table { key: Schema, value: Schema },
    /// Singleton canonical value.
    Cell(Schema),
    /// A nested owner classifies its fields at its privacy boundary.
    Owner(&'static [Field]),
}

/// Exact checked reconstruction of secondary state from authoritative sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DerivationCheck {
    /// Existing reconstruction implementation; root publication must run/check it.
    Rebuild(&'static str),
    /// A commitment over every canonical descendant of the named owners, which supply its
    /// authority; the procedure recomputes it from those values (a cold capture).
    Commitment(&'static str),
}

/// Four explicit authority classes. Names alone never select a class.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Role {
    /// Independent semantic authority with a canonical codec or explicit obligation.
    Canonical(Canonical),
    /// Secondary state, excluded as independent authority only after verification.
    Derived {
        /// Exact canonical/derived source identities required for reconstruction.
        sources: &'static [&'static str],
        /// Concrete source procedure or the still-required complete checker.
        check: DerivationCheck,
    },
    /// Authenticated historical authority, not the physical cache retaining it.
    History {
        /// Protocol object and finality boundary establishing this authority.
        source: &'static str,
        /// Concrete authentication/recovery owner.
        authentication: &'static str,
    },
    /// Pure physical machinery whose incidental value cannot affect consensus.
    Local(&'static str),
}

/// Disclosure is independently reviewed; canonical does not imply public rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Disclosure {
    /// No raw row witness may be published from this descriptor.
    CommitmentOnly,
    /// A physical owner has no canonical row witness.
    NotApplicable,
}

/// One actual owner field and its stable, explicitly assigned identity.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Field {
    /// Stable identity, independent of list order or Rust type location.
    pub id: &'static str,
    /// Reviewed authority class.
    pub role: Role,
    /// Fail-closed disclosure policy.
    pub disclosure: Disclosure,
}

impl Field {
    /// Register a field without granting any ability to disclose its values.
    pub(crate) const fn new(id: &'static str, role: Role) -> Self {
        Self {
            id,
            disclosure: match role {
                Role::Local(_) => Disclosure::NotApplicable,
                _ => Disclosure::CommitmentOnly,
            },
            role,
        }
    }
}

// The actual field pattern and typed references are generated from exactly the
// same entries as the descriptors. There is deliberately no fallback arm.
macro_rules! classified_owner {
    ($owner:ident, $check:ident, $registry:ident, readers = $readers:ident, {
        $( $(#[$attribute:meta])* $field:ident : $ty:ty => ($id:literal, $role:expr), release = $release:ident; )+
    }) => {
        classified_owner!($owner, $check, $registry, {
            $( $(#[$attribute])* $field : $ty => ($id, $role); )+
        });
        /// Exhaustive original reader releases, retained beyond enclosing fences.
        /// Slot names are physical custody metadata, separate from canonical field identity.
        pub(crate) struct $readers {
            $( $(#[$attribute])* pub(crate) $release:
                <$ty as crate::state::view_acquisition::StateFieldReader>::Releases, )+
        }
        impl $readers {
            pub(crate) fn new(owner: &$owner) -> Self {
                Self {
                    $( $(#[$attribute])* $release:
                        crate::state::view_acquisition::StateFieldReader::reader_releases(&owner.$field), )+
                }
            }
        }
    };
    ($owner:ident, $check:ident, $registry:ident, {
        $( $(#[$attribute:meta])* $field:ident : $ty:ty => ($id:literal, $role:expr); )+
    }) => {
        pub(crate) const $registry: &[Field] = &[
            $( $(#[$attribute])* Field::new($id, $role), )+
        ];
        fn $check(owner: &$owner) {
            let $owner { $( $(#[$attribute])* $field, )+ } = owner;
            $( $(#[$attribute])* let _: &$ty = $field; )+
        }
        const _: fn(&$owner) = $check;
    };
}
pub(crate) use classified_owner;

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: compose the bounded State cell slice into the complete State publication owner"
    )
)]
mod cell_snapshot;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: consume complete inventory admission in the State/Kura root publication owner"
    )
)]
mod complete;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: consume the content admission projection in the complete State root owner"
    )
)]
mod content_policy;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: consume the cryptographic admission projection in the complete State root owner"
    )
)]
mod crypto_policy;
mod domain_ownership;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: consume the fraud admission projection in the complete State root owner"
    )
)]
mod fraud_policy;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: consume the governance authority projection in the complete State root owner"
    )
)]
mod governance_policy;
// Construction-independent contract of the single keyed State commitment
// (`specs/sumeragi.md` §16). Nothing here is consensus state yet.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO(G.2, G.3): candidate constructions and the State publication owner consume the keyed commitment contract"
    )
)]
pub(crate) mod keyed_commitment;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: consume the typed lane-manifest cell in complete State-root publication"
    )
)]
mod lane_manifest_policy;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: bind the scoped table-leaf substrate to the complete State publication owner"
    )
)]
pub(crate) mod leaf;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: consume the exact static Nexus preimage in complete State root publication"
    )
)]
mod nexus_policy;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: consume the oracle policy projection in the complete State root owner"
    )
)]
mod oracle_policy;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: consume the pipeline policy projection in the complete State root owner"
    )
)]
mod pipeline_policy;
mod runtime;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: consume the runtime lane projection in the complete State root owner"
    )
)]
mod runtime_lane_policy;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: consume the settlement policy projection in the complete State root owner"
    )
)]
mod settlement_policy;
mod state;
pub(in crate::state) mod world;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "TODO: consume the ZK policy projection in the complete State root owner"
    )
)]
mod zk_policy;
/// Identities of every canonical table that the exact table catalog reads.
#[cfg(test)]
pub(in crate::state) use complete::table_capture::catalog_table_ids;
/// Classified fields of the concrete State owner.
pub(crate) const STATE_FIELDS: &[Field] = state::STATE_FIELDS;
/// Classified fields of the concrete heap-owned World data owner.
pub(crate) const WORLD_FIELDS: &[Field] = world::WORLD_FIELDS;

#[cfg(test)]
pub(in crate::state) mod inventory_test_support;
#[cfg(test)]
mod runtime_codec_tests;
#[cfg(test)]
mod tests;
