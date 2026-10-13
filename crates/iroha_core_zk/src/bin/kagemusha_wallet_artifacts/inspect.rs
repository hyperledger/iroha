//! Read-only inspection through the same strict source owners as wallet setup.

use std::time::Instant;

use iroha_core_zk::kagemusha_wallet_artifacts_v1::producer_inventory::{
    AuthenticatedProducerInventoryV1, EncodedDirectoryOriginalsV1, EncodedTransportV1,
    OperationQualificationProgressV1, ProducerInventoryV1, QQualificationProgressV1,
    TRANSPORT_MAX_BYTES_V1,
};

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Encoding {
    Raw,
    Zstd,
}

impl Encoding {
    pub(super) fn from_flag(flag: &str) -> Option<Self> {
        match flag {
            "--inspect-sources" => Some(Self::Raw),
            "--inspect-encoded-sources" => Some(Self::Zstd),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Zstd => "zstd",
        }
    }
}

pub(super) fn require_transport(
    inventory: &ProducerInventoryV1,
    transport: &EncodedTransportV1,
) -> io::Result<()> {
    let mut expected = BTreeMap::new();
    for original in &inventory.originals {
        for blob in [
            original.descriptor,
            original.verifying_key,
            original.proving_key,
        ] {
            if expected
                .insert(blob.sha256, blob)
                .is_some_and(|old| old != blob)
            {
                return Err(invalid("ambiguous signed original identity"));
            }
        }
    }
    if transport
        .originals()
        .iter()
        .map(|row| row.original)
        .ne(expected.into_values())
    {
        return Err(invalid(
            "encoded transport differs from signed original closure",
        ));
    }
    Ok(())
}

pub(super) fn open_sources(
    root: &PrivateDirectory,
    inventory: &AuthenticatedProducerInventoryV1,
    encoding: Encoding,
) -> io::Result<(Box<dyn OriginalSourceV1>, Option<Original>)> {
    let directory = root.path().join("wallet-originals");
    match encoding {
        Encoding::Raw => Ok((
            Box::new(DirectoryOriginalsV1::open_existing(
                directory,
                PROVING_KEY_MAX_BYTES_V1,
            )?),
            None,
        )),
        Encoding::Zstd => {
            let original = Original::open(
                root.path()
                    .join("transport.json")
                    .to_str()
                    .ok_or_else(|| invalid("transport path"))?,
                TRANSPORT_MAX_BYTES_V1,
                None,
            )?;
            let transport = EncodedTransportV1::from_json(&original.bytes)?;
            require_transport(inventory.inventory(), &transport)?;
            let source = EncodedDirectoryOriginalsV1::open_existing(directory, &transport)?;
            original.recheck()?;
            Ok((Box::new(source), Some(original)))
        }
    }
}

fn phase(encoding: Encoding, name: &str, started: Instant) {
    println!(
        "SOURCE_INSPECTION encoding={} phase={} elapsed_ms={}",
        encoding.label(),
        name,
        started.elapsed().as_millis(),
    );
}

/// Supplied scheme/manifest pins authenticate the carrier, never genesis or custody.
/// This traverses every exact source but never returns a wallet-open capability.
pub(super) fn sources(
    path: &str,
    scheme: &str,
    manifest: &str,
    encoding: Encoding,
) -> io::Result<()> {
    let total = Instant::now();
    let root = PrivateDirectory::open_exact(path)?;
    let pack = Original::open(
        root.path()
            .join("verifier-pack.norito")
            .to_str()
            .ok_or_else(|| invalid("carrier path"))?,
        iroha_core_zk::kagemusha_wallet_artifacts_v1::VERIFIER_PACK_MAX_BYTES_V1,
        None,
    )?;
    let catalog = Original::open(
        root.path()
            .join("producer-inventory.norito")
            .to_str()
            .ok_or_else(|| invalid("carrier path"))?,
        iroha_core_zk::kagemusha_wallet_artifacts_v1::producer_inventory::CATALOG_MAX_BYTES_V1,
        None,
    )?;
    let started = Instant::now();
    let installed = InstalledVerifierPackV1::load(
        &pack.bytes,
        InstallationV1 {
            scheme_id: digest(scheme)?,
            manifest_digest: digest(manifest)?,
        },
    )
    .map_err(io::Error::other)?;
    phase(encoding, "verifier_parameters", started);
    let inventory = installed
        .authenticate_producer_inventory(&catalog.bytes)
        .map_err(io::Error::other)?;
    let (mut originals, transport) = open_sources(&root, &inventory, encoding)?;
    let config = ReadConfig {
        maximum_bytes: PROVING_KEY_MAX_BYTES_V1,
        maximum_rows: 1 << 16,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    eprintln!(
        "Signed verifier pack and producer inventory accepted; qualifying every sigma source."
    );
    let started = Instant::now();
    let sigmas = inventory
        .qualify_sigmas_for_installation(&installed, originals.as_mut(), config)
        .map_err(io::Error::other)?;
    phase(encoding, "sigma", started);
    let started = Instant::now();
    let mut member_started = started;
    let programs = inventory
        .qualify_q_programs(
            &installed,
            &sigmas,
            originals.as_mut(),
            config,
            |event| match event {
                QQualificationProgressV1::Started { program_index } => {
                    eprintln!(
                        "Qualifying Q program {}/{}",
                        program_index + 1,
                        inventory.inventory().operations.len()
                    );
                    member_started = Instant::now();
                }
                QQualificationProgressV1::Completed { program_index } => {
                    phase(
                        encoding,
                        &format!("q_program_{program_index}"),
                        member_started,
                    );
                }
            },
        )
        .map_err(io::Error::other)?;
    phase(encoding, "q", started);
    let started = Instant::now();
    let mut member_started = started;
    let routes = inventory
        .qualify_operation_routes(&installed, &programs, originals.as_mut(), config, |event| {
            match event {
                OperationQualificationProgressV1::Started { route_index } => {
                    eprintln!(
                        "Qualifying operation route {}/{}",
                        route_index + 1,
                        inventory.inventory().routes.len()
                    );
                    member_started = Instant::now();
                }
                OperationQualificationProgressV1::Completed { route_index } => {
                    phase(encoding, &format!("route_{route_index}"), member_started);
                }
            }
        })
        .map_err(io::Error::other)?;
    phase(encoding, "routes", started);
    eprintln!("Qualifying complete Omega closure.");
    let started = Instant::now();
    let _omega = inventory
        .qualify_omega(&installed, &routes, originals.as_mut(), config)
        .map_err(io::Error::other)?;
    phase(encoding, "omega", started);
    pack.recheck()?;
    catalog.recheck()?;
    if let Some(transport) = transport {
        transport.recheck()?;
    }
    root.revalidate()?;
    phase(encoding, "total", total);
    println!(
        "Complete current-source artifact graph accepted. Genesis/finality, runtime installation and financial execution were not admitted."
    );
    Ok(())
}

#[cfg(test)]
#[path = "inspect/tests.rs"]
mod tests;
