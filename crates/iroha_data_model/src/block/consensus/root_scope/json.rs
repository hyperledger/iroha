//! Shared tagged scope grammar; all temporary strings use the caller's pool.

use norito::json::{
    self, JsonDeserialize,
    scratch::{OrdinaryScratch, ScratchDestination, key_text},
};

use super::{DataSpaceId, NetworkId, SumeragiRootScope};

fn invalid(message: &'static str) -> json::Error {
    json::Error::WithPos {
        msg: message,
        byte: 0,
        line: 1,
        col: 1,
    }
}

enum Content {
    Unit,
    Dataspace {
        parent_network_id: NetworkId,
        dataspace_id: DataSpaceId,
    },
}

fn content<D: ScratchDestination>(
    parser: &mut json::Parser<'_>,
    destination: &D,
) -> Result<Content, D::Error> {
    parser.skip_ws();
    if parser.input().as_bytes().get(parser.position()) == Some(&b'n') {
        parser.parse_null()?;
        return Ok(Content::Unit);
    }
    let mut parent_network_id = None;
    let mut dataspace_id = None;
    let mut object = json::MapVisitor::new(parser)?;
    while let Some(key) = destination.key(&mut object)? {
        match key_text(&key) {
            "parent_network_id" => {
                if parent_network_id.is_some() {
                    return Err(invalid("duplicate parent network identity").into());
                }
                parent_network_id = Some(object.parse_value_with_parser_typed(|parser| {
                    NetworkId::json_decode_with(parser, destination)
                })?);
            }
            "dataspace_id" => {
                if dataspace_id.is_some() {
                    return Err(invalid("duplicate data space identity").into());
                }
                dataspace_id = Some(object.parse_value::<DataSpaceId>()?);
            }
            // The existing scope enum permits unknown fields at both levels.
            // Preserve that owner policy without building or reparsing a Value.
            _ => object.skip_value()?,
        }
    }
    object.finish()?;
    Ok(Content::Dataspace {
        parent_network_id: parent_network_id
            .ok_or_else(|| invalid("missing parent network identity"))?,
        dataspace_id: dataspace_id.ok_or_else(|| invalid("missing data space identity"))?,
    })
}

impl SumeragiRootScope {
    pub(crate) fn json_decode_with<D: ScratchDestination>(
        parser: &mut json::Parser<'_>,
        destination: &D,
    ) -> Result<Self, D::Error> {
        let mut kind = None;
        let mut value = None;
        let mut object = json::MapVisitor::new(parser)?;
        while let Some(key) = destination.key(&mut object)? {
            match key_text(&key) {
                "kind" => {
                    if kind.is_some() {
                        return Err(invalid("duplicate root scope kind").into());
                    }
                    kind = Some(object.parse_value_with_parser_typed(
                        |parser| -> Result<_, D::Error> {
                            let text = destination.string(parser)?;
                            match text.as_ref() {
                                "global" => Ok(false),
                                "dataspace" => Ok(true),
                                _ => Err(invalid("unknown root scope kind").into()),
                            }
                        },
                    )?);
                }
                "value" => {
                    if value.is_some() {
                        return Err(invalid("duplicate root scope value").into());
                    }
                    value =
                        Some(object.parse_value_with_parser_typed(|parser| {
                            content(parser, destination)
                        })?);
                }
                _ => object.skip_value()?,
            }
        }
        object.finish()?;
        match (
            kind.ok_or_else(|| invalid("missing root scope kind"))?,
            value.ok_or_else(|| invalid("missing root scope value"))?,
        ) {
            (false, Content::Unit) => Ok(Self::Global),
            (
                true,
                Content::Dataspace {
                    parent_network_id,
                    dataspace_id,
                },
            ) => Ok(Self::Dataspace {
                parent_network_id,
                dataspace_id,
            }),
            _ => Err(invalid("root scope kind/content mismatch").into()),
        }
    }
}
impl JsonDeserialize for SumeragiRootScope {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        Self::json_decode_with(parser, &OrdinaryScratch)
    }
}

// Tape reads delegate to the same ordinary typed kernel, as the former derive did.
impl<'a> json::FastFromJson<'a> for SumeragiRootScope {
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
    fn root_scope_uses_one_order_independent_tagged_relation() {
        let pool = AllocationBudget::new(4096);
        for source in [
            r#"{"kind":"global","value":null}"#,
            r#"{"value":null,"ki\u006ed":"global","extra":[0]}"#,
        ] {
            assert_eq!(
                json::from_str::<SumeragiRootScope>(source).unwrap(),
                SumeragiRootScope::Global
            );
            assert_eq!(
                SumeragiRootScope::json_decode_with(
                    &mut json::Parser::new(source),
                    &AdmittedScratch::new(&pool)
                )
                .unwrap(),
                SumeragiRootScope::Global
            );
            assert_eq!(pool.reserved_bytes(), 0);
        }
        for source in [
            r#"{"kind":"global"}"#,
            r#"{"kind":"dataspace","value":null}"#,
            r#"{"kind":"global","value":null,"value":null}"#,
            r#"{"kind":"global","ki\u006ed":"global","value":null}"#,
        ] {
            assert!(json::from_str::<SumeragiRootScope>(source).is_err());
            assert!(
                SumeragiRootScope::json_decode_with(
                    &mut json::Parser::new(source),
                    &AdmittedScratch::new(&pool)
                )
                .is_err()
            );
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}
