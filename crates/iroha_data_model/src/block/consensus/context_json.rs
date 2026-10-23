//! Shared scalar signed-context grammar, with original-pool text scratch.

use super::{DataAvailabilityLayout, SumeragiGenesisContextParameters, SumeragiRootScope};
use norito::json::{
    self, JsonDeserialize,
    scratch::{OrdinaryScratch, ScratchDestination, key_text},
};

fn invalid(message: &'static str) -> json::Error {
    json::Error::WithPos {
        msg: message,
        byte: 0,
        line: 1,
        col: 1,
    }
}
fn hash<D: ScratchDestination>(
    parser: &mut json::Parser<'_>,
    destination: &D,
) -> Result<[u8; 32], D::Error> {
    let text = destination.string(parser)?;
    let mut bytes = [0; 32];
    // Same fixed-width hexadecimal scalar as the canonical [u8;32] JSON wire.
    // Both cases remain accepted; output remains the existing uppercase writer.
    hex::decode_to_slice(text.as_ref(), &mut bytes)
        .map_err(|_| invalid("expected 32-byte hexadecimal context hash"))?;
    Ok(bytes)
}
impl SumeragiGenesisContextParameters {
    pub(crate) fn json_decode_with<D: ScratchDestination>(
        parser: &mut json::Parser<'_>,
        destination: &D,
    ) -> Result<Self, D::Error> {
        let mut root_scope = None;
        let mut da_layout = None;
        let mut nexus_amx_context_hash = None;
        let mut execution_policy_hash = None;
        let mut object = json::MapVisitor::new(parser)?;
        while let Some(key) = destination.key(&mut object)? {
            macro_rules! field {
                ($field:ident,$read:expr) => {{
                    if $field.is_some() {
                        return Err(invalid(concat!(
                            "duplicate signed context field: ",
                            stringify!($field)
                        ))
                        .into());
                    }
                    $field = Some(object.parse_value_with_parser_typed($read)?);
                }};
            }
            match key_text(&key) {
                "root_scope" => field!(root_scope, |parser| SumeragiRootScope::json_decode_with(
                    parser,
                    destination
                )),
                "da_layout" => field!(
                    da_layout,
                    |parser| DataAvailabilityLayout::json_decode_with(parser, destination)
                ),
                "nexus_amx_context_hash" => {
                    field!(nexus_amx_context_hash, |parser| hash(parser, destination))
                }
                "execution_policy_hash" => {
                    field!(execution_policy_hash, |parser| hash(parser, destination))
                }
                _ => return Err(invalid("unknown signed context field").into()),
            }
        }
        object.finish()?;
        macro_rules! required {
            ($field:ident) => {
                $field.ok_or_else(|| {
                    invalid(concat!(
                        "missing signed context field: ",
                        stringify!($field)
                    ))
                })?
            };
        }
        Ok(Self {
            root_scope: required!(root_scope),
            da_layout: required!(da_layout),
            nexus_amx_context_hash: required!(nexus_amx_context_hash),
            execution_policy_hash: required!(execution_policy_hash),
        })
    }
}
impl JsonDeserialize for SumeragiGenesisContextParameters {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        Self::json_decode_with(parser, &OrdinaryScratch)
    }
}

// Tape reads delegate to the same ordinary typed kernel, as the former derive did.
impl<'a> json::FastFromJson<'a> for SumeragiGenesisContextParameters {
    fn parse(
        walker: &mut json::TapeWalker<'a>,
        _arena: &mut json::Arena,
    ) -> Result<Self, norito::Error> {
        walker.ensure_document_depth()?;
        let mut parser = json::Parser::new_at(walker.input(), walker.raw_pos());
        let value = Self::json_deserialize(&mut parser).map_err(norito::Error::from)?;
        walker.sync_to_raw(parser.position());
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_allocation::AllocationBudget;
    use norito::json::scratch::AdmittedScratch;

    #[test]
    fn signed_context_matches_ordinary_with_lowercase_hex_and_funded_escapes() {
        let expected = SumeragiGenesisContextParameters::recommended();
        let source = json::to_json(&expected).unwrap();
        let escaped = source.replace("nexus_amx_context_hash", "nexus_amx_context_ha\\u0073h");
        let pool = AllocationBudget::new(4096);
        for source in [&source, &escaped] {
            let actual = SumeragiGenesisContextParameters::json_decode_with(
                &mut json::Parser::new(source),
                &AdmittedScratch::new(&pool),
            )
            .unwrap();
            assert_eq!(actual, expected);
            assert_eq!(
                json::from_str::<SumeragiGenesisContextParameters>(source).unwrap(),
                actual
            );
            assert_eq!(pool.reserved_bytes(), 0);
        }
        let lower = source.replace(
            &hex::encode_upper(expected.execution_policy_hash),
            &hex::encode(expected.execution_policy_hash),
        );
        assert_eq!(
            json::from_str::<SumeragiGenesisContextParameters>(&lower).unwrap(),
            expected
        );
        let duplicate = source.replacen(
            '{',
            "{\"root_scope\":{\"kind\":\"global\",\"value\":null},",
            1,
        );
        assert!(json::from_str::<SumeragiGenesisContextParameters>(&duplicate).is_err());
        assert!(
            SumeragiGenesisContextParameters::json_decode_with(
                &mut json::Parser::new(&duplicate),
                &AdmittedScratch::new(&pool)
            )
            .is_err()
        );
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
