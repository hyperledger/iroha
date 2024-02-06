//! Build script that auto-updates sample binaries from sources.

use std::{fs, path::PathBuf};

use eyre::Result;
use iroha_data_model::{account::NewAccount, domain::NewDomain, prelude::*};
use parity_scale_codec::Encode;
use serde::de::DeserializeOwned;

fn main() {
    sample_into_binary_file::<NewAccount>("account").expect("Failed to encode into account.bin.");

    sample_into_binary_file::<NewDomain>("domain").expect("Failed to encode into domain.bin.");

    sample_into_binary_file::<Trigger<TriggeringEventFilterBox>>("trigger")
        .expect("Failed to encode into trigger.bin.");
}

fn sample_into_binary_file<T>(filename: &str) -> Result<()>
where
    T: Encode + DeserializeOwned,
{
    let mut path_to = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path_to.push("samples/");
    path_to.push(filename);

    let path_to_json = path_to.with_extension("json");
    let path_to_binary = path_to.with_extension("bin");

    println!("cargo:rerun-if-changed={}", path_to_json.to_str().unwrap());
    let buf = fs::read_to_string(path_to_json)?;

    let sample = serde_json::from_str::<T>(buf.as_str())?;

    let buf = sample.encode();

    fs::write(path_to_binary, buf)?;

    Ok(())
}
