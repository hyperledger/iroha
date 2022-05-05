//! Parity Scale decoder tool for Iroha data types. For usage run with `--help`

#![allow(clippy::print_stdout, clippy::use_debug, clippy::unnecessary_wraps)]

use std::{collections::BTreeMap, fmt::Debug, fs, io, path::PathBuf};

use clap::Parser;
use colored::*;
use eyre::{eyre, Result};
use parity_scale_codec::Decode;

mod generate_map;
use generate_map::generate_map;

/// Parity Scale decoder tool for Iroha data types
#[derive(Debug, Parser)]
#[clap(version, about, author)]
enum Args {
    /// Show all available types
    ListTypes,
    /// Decode type from binary
    Decode(DecodeArgs),
}

#[derive(Debug, clap::Args)]
struct DecodeArgs {
    /// Path to the binary with encoded Iroha structure
    binary: PathBuf,
    /// Type that is expected to be encoded in binary.
    /// If not specified then a guess will be attempted
    #[clap(short, long = "type")]
    type_id: Option<String>,
}

/// Function pointer to [`DumpDecoded::dump_decoded()`]
///
/// Function pointer is used cause trait object can not be used
/// due to [`Sized`] bound in [`Decode`] trait
pub type DumpDecodedPtr = fn(&[u8], &mut dyn io::Write) -> Result<(), eyre::Error>;

/// Map (Type Name -> `dump_decode()` ptr)
pub type DumpDecodedMap = BTreeMap<String, DumpDecodedPtr>;

/// Types implementing this trait can be decoded from bytes
/// with *Parity Scale Codec* and dumped to something implementing [`Write`]
pub trait DumpDecoded: Debug + Decode {
    /// Decode `Self` from `input` and dump to `w`
    ///
    /// # Errors
    /// - If decoding from *Parity Scale Codec* fails
    /// - If writing into `w` fails
    fn dump_decoded(mut input: &[u8], w: &mut dyn io::Write) -> Result<(), eyre::Error> {
        let obj = <Self as Decode>::decode(&mut input)?;
        #[allow(clippy::use_debug)]
        writeln!(w, "{:#?}", obj)?;
        Ok(())
    }
}

impl<T: Debug + Decode> DumpDecoded for T {}

fn main() -> Result<()> {
    let args = Args::parse();

    let map = generate_map();
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());

    match args {
        Args::Decode(decode_args) => {
            let decoder = Decoder::new(decode_args, &map);
            decoder.decode(&mut writer)
        }
        Args::ListTypes => list_types(&map, &mut writer),
    }
}

/// Type decoder
struct Decoder<'map> {
    args: DecodeArgs,
    map: &'map DumpDecodedMap,
}

impl<'map> Decoder<'map> {
    /// Create new `Decoder` with `args` and `map`
    pub fn new(args: DecodeArgs, map: &'map DumpDecodedMap) -> Self {
        Self { args, map }
    }

    /// Decode type and print to `writer`
    pub fn decode<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let bytes = fs::read(self.args.binary.clone())?;

        if let Some(type_id) = &self.args.type_id {
            return self.decode_by_type(type_id, &bytes, writer);
        }
        self.decode_by_guess(&bytes, writer)
    }

    /// Decode concrete `type` from `bytes` and print to `writer`
    fn decode_by_type<W: io::Write>(
        &self,
        type_id: &str,
        bytes: &[u8],
        writer: &mut W,
    ) -> Result<()> {
        self.map.get(type_id).map_or_else(
            || Err(eyre!("Unknown type: `{type_id}`")),
            |dump_decoded| dump_decoded(bytes, writer),
        )
    }

    /// Try to decode every type from `bytes` and print to `writer`
    ///
    /// TODO: Can be parallelized when there will be too many types
    fn decode_by_guess<W: io::Write>(&self, bytes: &[u8], writer: &mut W) -> Result<()> {
        let count = self
            .map
            .iter()
            .filter_map(|(type_name, dump_decoded)| {
                let mut buf = Vec::new();
                dump_decoded(bytes, &mut buf)
                    .ok()
                    .and_then(|_| String::from_utf8(buf).ok())
                    .and_then(|formatted| {
                        writeln!(writer, "{}:\n{}", type_name.italic().cyan(), formatted).ok()
                    })
            })
            .count();
        match count {
            0 => writeln!(writer, "No compatible types found"),
            1 => writeln!(writer, "{} compatible type found", "1".bold()),
            n => writeln!(writer, "{} compatible types found", n.to_string().bold()),
        }
        .map_err(Into::into)
    }
}

/// Print all supported types from `map` to `writer`
fn list_types<W: io::Write>(map: &DumpDecodedMap, writer: &mut W) -> Result<()> {
    for key in map.keys() {
        writeln!(writer, "{key}")?;
    }
    if !map.is_empty() {
        writeln!(writer)?;
    }

    match map.len() {
        0 => writeln!(writer, "No type is supported"),
        1 => writeln!(writer, "{} type is supported", "1".bold()),
        n => writeln!(writer, "{} types are supported", n.to_string().bold()),
    }
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_account_sample() {
        decode_sample(
            "account.bin",
            String::from("iroha_data_model::account::Account"),
            r###"Account {
    id: Id {
        name: "alice",
        domain_id: Id {
            name: "wonderland",
        },
    },
    assets: {},
    signatories: {},
    permission_tokens: {},
    signature_check_condition: SignatureCheckCondition(
        EvaluatesTo {
            expression: ContainsAny(
                ContainsAny {
                    collection: EvaluatesTo {
                        expression: ContextValue(
                            ContextValue {
                                value_name: "transaction_signatories",
                            },
                        ),
                        _value_type: PhantomData,
                    },
                    elements: EvaluatesTo {
                        expression: ContextValue(
                            ContextValue {
                                value_name: "account_signatories",
                            },
                        ),
                        _value_type: PhantomData,
                    },
                },
            ),
            _value_type: PhantomData,
        },
    ),
    metadata: Metadata {
        map: {
            "hat": Name(
                "white",
            ),
        },
    },
    roles: {},
}
"###,
        );
    }

    #[test]
    fn decode_domain_sample() {
        decode_sample(
            "domain.bin",
            String::from("iroha_data_model::domain::Domain"),
            r###"Domain {
    id: Id {
        name: "wonderland",
    },
    accounts: {},
    asset_definitions: {},
    logo: Some(
        IpfsPath(
            "/ipfs/Qme7ss3ARVgxv6rXqVPiikMJ8u2NLgmgszg13pYrDKEoiu",
        ),
    ),
    metadata: Metadata {
        map: {
            "Is_Jabberwocky_alive": Bool(
                true,
            ),
        },
    },
}
"###,
        );
    }

    #[test]
    fn decode_trigger_sample() {
        // This test is extremely awkward to update. There are no
        // instructions for how to do so, and I'm willing to bet that
        // any of the community members who want to adjust the
        // triggers will not know what to do.
        decode_sample(
            "trigger.bin",
            String::from("iroha_data_model::trigger::Trigger"),
            r###"Trigger {
    id: Id {
        name: "mint_rose",
    },
    action: Action {
        executable: Instructions(
            [
                Mint(
                    MintBox {
                        object: EvaluatesTo {
                            expression: Raw(
                                U32(
                                    1,
                                ),
                            ),
                            _value_type: PhantomData,
                        },
                        destination_id: EvaluatesTo {
                            expression: Raw(
                                Id(
                                    AssetId(
                                        Id {
                                            definition_id: DefinitionId {
                                                name: "rose",
                                                domain_id: Id {
                                                    name: "wonderland",
                                                },
                                            },
                                            account_id: Id {
                                                name: "alice",
                                                domain_id: Id {
                                                    name: "wonderland",
                                                },
                                            },
                                        },
                                    ),
                                ),
                            ),
                            _value_type: PhantomData,
                        },
                    },
                ),
            ],
        ),
        repeats: Indefinitely,
        technical_account: Id {
            name: "alice",
            domain_id: Id {
                name: "wonderland",
            },
        },
        filter: Data(
            BySome(
                ByAccount(
                    AcceptAll,
                ),
            ),
        ),
        metadata: Metadata {
            map: {},
        },
    },
}
"###,
        );
    }

    #[allow(clippy::expect_used)]
    fn decode_sample(sample_path: &str, type_id: String, expected_output: &str) {
        let mut binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        binary.push("samples/");
        binary.push(sample_path);
        let args = DecodeArgs {
            binary,
            type_id: Some(type_id),
        };

        let map = generate_map();
        let decoder = Decoder::new(args, &map);
        let mut buf = Vec::new();
        decoder.decode(&mut buf).expect("Decoding failed");
        let actual = String::from_utf8(buf).expect("valid UTF-8");
        // Predictably,  the string-based comparison is white-space sensitive.
        println!("{}\n{}", actual, expected_output);
        assert_eq!(actual, expected_output);
    }
}
