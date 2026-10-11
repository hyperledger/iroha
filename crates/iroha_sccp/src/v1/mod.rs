//! Network-free SCCP v1 primitives (spec `specs/sccp.md` §3).
//!
//! This module holds the canonical contract-visible encodings that Taira
//! nodes, destination contracts, wallets and tools must agree on byte for
//! byte: profile identities and lanes, the transfer payload codec and amount
//! rules, payload and message hashes, block commitment and history trees,
//! EIP-712 digests, roster digests, signature checks, the node-local bridge
//! key file, TON cell hashing and EVM ABI helpers. Nothing here performs I/O;
//! network access lives in `iroha_sccp_rpc`.
//!
//! The revision-5 finality reference (`specs/sccp.md` §3.4, §3.6–§3.8, §5.1, §5.2.2) is in
//! six modules: [`finality`] holds the finality header `X`, `QC_FIXED`, the certified result
//! `R`, the Commit preimage and the destination verification relation
//! ([`finality::verify_certificate`]); [`committee`] the committee root and geometry, the
//! EVM point forms and the destination committee state machine; [`evidence`] the consensus
//! anchors and the forgery-evidence identity; [`control`] the 199-byte control leaf;
//! [`destination`] the executable model of the destination contracts, EVM and TON
//! ([`destination::Destination`]); [`destination_abi`] their selectors, event topics and
//! the shared error table with its TON exit codes.
//!
//! TODO: WP-S1 deletes the attestation-model modules ([`eip712`], [`roster`], [`signature`],
//! [`key_file`]), the attestation-based verifiers of [`proof`] and the revision-4 parts of
//! [`constants`]; WP-S4 deletes the 126-byte control leaf of [`hashes`]. Until then they
//! stay beside the revision-5 modules, and a name that exists in both is the revision-5
//! one only in the six modules above.

/// Declare a field-less error enum with `Debug`, `Display` and `std::error::Error`.
macro_rules! unit_error {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $( $(#[$variant_meta:meta])* $variant:ident => $message:literal, )*
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        $vis enum $name {
            $( $(#[$variant_meta])* $variant, )*
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str(match self {
                    $( Self::$variant => $message, )*
                })
            }
        }

        impl std::error::Error for $name {}
    };
}

pub mod amount;
pub mod committee;
pub mod constants;
pub mod control;
pub mod destination;
pub mod destination_abi;
pub mod eip712;
pub mod evidence;
pub mod evm_abi;
pub mod finality;
pub mod hashes;
pub mod history;
pub mod key_file;
pub mod merkle;
pub mod network;
pub mod payload;
pub mod proof;
pub mod roster;
pub mod signature;
pub mod ton_cell;

#[cfg(test)]
mod tests {
    unit_error! {
        /// Macro smoke-test error.
        enum Probe {
            /// First.
            First => "first message",
            /// Second.
            Second => "second message",
        }
    }

    #[test]
    fn unit_error_displays_its_messages() {
        assert_eq!(Probe::First.to_string(), "first message");
        assert_eq!(Probe::Second.to_string(), "second message");
        let boxed: Box<dyn std::error::Error> = Box::new(Probe::Second);
        assert_eq!(boxed.to_string(), "second message");
    }
}
