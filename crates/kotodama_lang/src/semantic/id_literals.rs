//! Compile-time validation of typed-identifier string literals.
//!
//! `AccountId::parse("...")` and the other typed identifier constructors lower
//! a string literal into a canonical Norito pointer payload. Validating the
//! literal during semantic analysis lets `koto check` and the editor report a
//! mistyped identifier on the literal itself, with the same parsers lowering
//! uses and the session's chain discriminant. The checks never depend on host
//! state other than that discriminant, so results are identical on every node.
use iroha_data_model::account::{AccountId, address::AccountAddress};
use kotodama_surface::builtins::PointerConstructor;

/// A rejected typed-identifier literal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InvalidIdLiteral {
    /// Primary message naming the constructor and the problem.
    pub(crate) message: String,
    /// Site-specific remediation.
    pub(crate) help: String,
    /// Canonical spelling when a width-only rewrite yields a valid literal.
    pub(crate) canonical: Option<String>,
}

/// Full-width katakana and their half-width I105 forms (U+FF66..=U+FF9D).
///
/// Canonical I105 literals use half-width katakana. `ヰ` and `ヱ` have no
/// half-width forms and stay full-width, so a generic NFKC normalization would
/// rewrite in the wrong direction; this table is the exact inverse width map.
const FULL_WIDTH_KANA: &str = "ヲァィゥェォャュョッーアイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワン";
const HALF_WIDTH_KANA: &str = "ｦｧｨｩｪｫｬｭｮｯｰｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ";

/// Rewrite full-width katakana and full-width ASCII to their half-width forms.
fn half_width(raw: &str) -> String {
    raw.chars()
        .map(|character| {
            if let Some(index) = FULL_WIDTH_KANA.chars().position(|kana| kana == character) {
                return HALF_WIDTH_KANA
                    .chars()
                    .nth(index)
                    .expect("width tables have equal length");
            }
            match u32::from(character) {
                code @ 0xFF01..=0xFF5E => char::from_u32(code - 0xFF01 + 0x21).unwrap_or(character),
                _ => character,
            }
        })
        .collect()
}

fn account_help(error: &str) -> &'static str {
    match error {
        "ERR_CHECKSUM_MISMATCH" => {
            "The I105 checksum does not match, so the literal was probably mistyped or truncated. \
             Copy the account identifier exactly as printed, or re-encode it with \
             `iroha tools address convert`."
        }
        _ => {
            "Account literals are canonical I105 identifiers for this network. Copy the identifier \
             exactly as printed, or re-encode it with `iroha tools address convert`."
        }
    }
}

fn validate_account(raw: &str, expected: u16) -> Result<(), InvalidIdLiteral> {
    if raw.contains('@') {
        // Alias-shaped literals are resolved by the host at execution time.
        return Ok(());
    }
    if let Ok(found) = AccountAddress::i105_discriminant(raw)
        && found != expected
    {
        return Err(InvalidIdLiteral {
            message: format!(
                "AccountId literal is encoded for chain discriminant {found} but this build targets {expected} (ERR_UNEXPECTED_NETWORK_PREFIX)"
            ),
            help: format!(
                "Re-encode the account for chain discriminant {expected} with `iroha tools address convert`, \
                 or compile for the network the literal belongs to."
            ),
            canonical: None,
        });
    }
    let error = match AccountId::parse_encoded(raw) {
        Ok(_) => return Ok(()),
        Err(error) => error.to_string(),
    };
    let rewritten = half_width(raw);
    if rewritten != raw && AccountId::parse_encoded(&rewritten).is_ok() {
        return Err(InvalidIdLiteral {
            message: "AccountId literal uses full-width characters".to_owned(),
            help: "Canonical I105 literals write katakana in half-width form (only `ヰ` and `ヱ` stay \
                   full-width); an input method probably widened them. Use the half-width spelling."
                .to_owned(),
            canonical: Some(rewritten),
        });
    }
    Err(InvalidIdLiteral {
        message: format!("invalid AccountId literal `{raw}`: {error}"),
        help: account_help(&error).to_owned(),
        canonical: None,
    })
}

fn invalid(
    type_name: &str,
    raw: &str,
    error: impl std::fmt::Display,
    help: &str,
) -> InvalidIdLiteral {
    InvalidIdLiteral {
        message: format!("invalid {type_name} literal `{raw}`: {error}"),
        help: help.to_owned(),
        canonical: None,
    }
}

/// Validate one typed-identifier constructor literal for `chain_discriminant`.
///
/// Constructors whose payloads are not identifiers (JSON, blobs, proofs,
/// descriptors) are validated elsewhere and always pass here.
pub(crate) fn validate(
    constructor: PointerConstructor,
    raw: &str,
    chain_discriminant: u16,
) -> Result<(), InvalidIdLiteral> {
    const COPY_HELP: &str = "Copy the identifier exactly as printed by `iroha` tooling.";
    match constructor {
        PointerConstructor::AccountId => validate_account(raw, chain_discriminant),
        PointerConstructor::AssetDefinition => {
            iroha_data_model::asset::id::AssetDefinitionId::parse_address_literal(raw)
                .map(|_| ())
                .map_err(|error| {
                    invalid(
                        "AssetDefinitionId",
                        raw,
                        error,
                        "Asset definition identifiers are checksummed Base58 address literals; \
                         a wrong or missing character fails the checksum. Copy the identifier exactly \
                         as printed by `iroha` tooling.",
                    )
                })
        }
        PointerConstructor::AssetId => raw
            .parse::<iroha_data_model::asset::id::AssetId>()
            .map(|_| ())
            .map_err(|error| invalid("AssetId", raw, error, COPY_HELP)),
        PointerConstructor::NftId => raw
            .parse::<iroha_data_model::nft::NftId>()
            .map(|_| ())
            .map_err(|error| invalid("NftId", raw, error, COPY_HELP)),
        PointerConstructor::Name => raw
            .parse::<iroha_model_base::name::Name>()
            .map(|_| ())
            .map_err(|error| {
                invalid(
                    "Name",
                    raw,
                    error,
                    "Names are non-empty and may not contain whitespace or reserved separators.",
                )
            }),
        PointerConstructor::Domain | PointerConstructor::DomainId => {
            iroha_model_base::domain::DomainId::parse_fully_qualified(raw)
                .map(|_| ())
                .map_err(|error| invalid("DomainId", raw, error, COPY_HELP))
        }
        PointerConstructor::DataSpaceId => {
            let numeric = match raw.strip_prefix("0x") {
                Some(hex) => u64::from_str_radix(hex, 16).is_ok(),
                None => raw.parse::<u64>().is_ok(),
            };
            if numeric {
                Ok(())
            } else {
                Err(InvalidIdLiteral {
                    message: format!(
                        "invalid DataSpaceId literal `{raw}`: expected an unsigned integer"
                    ),
                    help: "DataSpaceId literals are decimal integers such as `DataSpaceId::parse(\"0\")`."
                        .to_owned(),
                    canonical: None,
                })
            }
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SORA: u16 = 753;
    const TEST: u16 = 369;

    #[test]
    fn width_table_inverts_nfkc_for_every_kana() {
        assert_eq!(
            FULL_WIDTH_KANA.chars().count(),
            HALF_WIDTH_KANA.chars().count()
        );
        assert_eq!(half_width("ｱア"), "ｱｱ");
        assert_eq!(half_width("ヰヱ"), "ヰヱ");
        assert_eq!(half_width("ＡＢ１"), "AB1");
    }

    #[test]
    fn invalid_identifier_literals_explain_the_problem() {
        let checksum = validate(PointerConstructor::AccountId, "soraﾛ1QﾉｳﾇmE", SORA)
            .expect_err("truncated account literal");
        assert!(
            checksum.message.starts_with("invalid AccountId literal"),
            "{checksum:?}"
        );
        let dataspace = validate(PointerConstructor::DataSpaceId, "zero", SORA)
            .expect_err("non-numeric dataspace");
        assert!(dataspace.help.contains("decimal integers"), "{dataspace:?}");
        validate(PointerConstructor::DataSpaceId, "0", SORA).expect("numeric dataspace");
        validate(PointerConstructor::DataSpaceId, "0x10", TEST).expect("hex dataspace");
        let asset = validate(PointerConstructor::AssetDefinition, "not-base58", SORA)
            .expect_err("asset definition checksum");
        assert!(asset.message.contains("AssetDefinitionId"), "{asset:?}");
        validate(PointerConstructor::Json, "{}", SORA).expect("non-identifier payloads pass");
    }

    #[test]
    fn account_literals_report_chain_discriminant_and_width_problems() {
        let literal = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
        validate(PointerConstructor::AccountId, literal, SORA).expect("canonical sora literal");
        let network = validate(PointerConstructor::AccountId, literal, TEST)
            .expect_err("sora literal under the test discriminant");
        assert_eq!(
            network.message,
            "AccountId literal is encoded for chain discriminant 753 but this build targets 369 (ERR_UNEXPECTED_NETWORK_PREFIX)"
        );
        let widened = literal.replace('ﾛ', "ロ").replace('ﾉ', "ノ");
        let width = validate(PointerConstructor::AccountId, &widened, SORA)
            .expect_err("full-width kana are not canonical");
        assert_eq!(width.canonical.as_deref(), Some(literal));
    }
}
