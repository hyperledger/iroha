//! Exact signed activation custody before its first network submission.
//!
//! The driver receipt is controller-observed DATA, not a signature or finality proof.
//! Native separately authenticates the signed wire and later certified ledger execution.
use super::*;

pub(super) fn closed(value: &norito::json::Value, fields: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or_else(|| eyre!("object required"))?;
    ensure!(
        object.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == fields.iter().copied().collect(),
        "exact fields required"
    );
    Ok(())
}

pub(super) fn selection(value: &norito::json::Value) -> Result<()> {
    closed(value, &["path", "sha256"])?;
    let path = value["path"]
        .as_str()
        .ok_or_else(|| eyre!("original path required"))?;
    ensure!(
        !path.is_empty() && path.len() <= 4096 && Path::new(path).is_absolute(),
        "bounded absolute path required"
    );
    digest(&value["sha256"])?;
    Ok(())
}

pub(super) fn require_command(command: &norito::json::Value, phase: &str) -> Result<()> {
    let selected = match phase {
        "funding" => "target",
        "activation-retained" => "retention",
        _ => bail!("unknown activation command phase"),
    };
    closed(
        command,
        &[
            "schema",
            "phase",
            "setup_sha256",
            "previous_sha256",
            selected,
        ],
    )?;
    ensure!(
        command["schema"].as_str() == Some("iroha.kagemusha.real-network-command.v1")
            && command["phase"].as_str() == Some(phase),
        "activation command schema/phase"
    );
    digest(&command["setup_sha256"])?;
    digest(&command["previous_sha256"])?;
    selection(&command[selected])
}

fn decimal(value: &norito::json::Value) -> Result<u64> {
    let text = value
        .as_str()
        .ok_or_else(|| eyre!("decimal string required"))?;
    let parsed = text.parse::<u64>()?;
    ensure!(parsed.to_string() == text, "canonical decimal required");
    Ok(parsed)
}

fn require_retention(receipt: &norito::json::Value, wire: &[u8], entrypoint: &[u8]) -> Result<()> {
    closed(
        receipt,
        &[
            "schema",
            "action",
            "signedWireSHA256",
            "signedWireBytes",
            "nativeResult",
            "entrypointHex",
            "nativeReturnedTicks",
            "invocation",
            "sequence",
        ],
    )?;
    ensure!(
        receipt["schema"].as_str() == Some("iroha.kagemusha.wallet-activation-retained.v1")
            && receipt["action"].as_str() == Some("retain-activation")
            && receipt["nativeResult"].as_str() == Some("awaiting"),
        "initial successful native retention required"
    );
    ensure!(
        digest(&receipt["signedWireSHA256"])? == Sha256::digest(wire).as_slice()
            && decimal(&receipt["signedWireBytes"])? == u64::try_from(wire.len())?,
        "retained signed wire differs"
    );
    // Native derives the attempt's route selector from the retained wire itself.
    ensure!(
        digest(&receipt["entrypointHex"])? == entrypoint,
        "retained entrypoint differs"
    );
    let invocation = receipt["invocation"]
        .as_str()
        .ok_or_else(|| eyre!("invocation required"))?;
    // Invocation is an opaque UUID-shaped driver identity. Apple emits uppercase and
    // Android lowercase; preserve the original bytes rather than rewriting either.
    ensure!(
        invocation.len() == 36
            && invocation.bytes().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            }),
        "UUID invocation required"
    );
    ensure!(
        decimal(&receipt["sequence"])? < 10_000,
        "driver sequence bound"
    );
    ensure!(
        decimal(&receipt["nativeReturnedTicks"])? > 0,
        "native return observation required"
    );
    Ok(())
}

fn prepared(
    setup_sha: &str,
    registration: &[u8],
    command: &[u8],
    target: &[u8],
    transaction: &SignedTransaction,
) -> Result<(Vec<u8>, Vec<u8>)> {
    digest(&setup_sha.into())?;
    let wire = transaction.encode_wire_v1()?;
    ensure!(
        !wire.is_empty() && wire.len() <= ORIGINAL_MAX,
        "signed wire extent"
    );
    let receipt = norito::json::to_vec(&norito::json!({
        "schema":"iroha.kagemusha.network-activation-prepared.v1", "setup_sha256":setup_sha,
        "registration_sha256":(hash(registration)), "funding_command_sha256":(hash(command)),
        "target_sha256":(hash(target)), "transaction_hash_hex":(hex::encode(transaction.hash().as_ref())),
        "signed_transaction":{"name":"funding/activate-signed.wire", "bytes":(wire.len()), "sha256":(hash(&wire))}
    }))?;
    ensure!(receipt.len() <= 16 << 10, "prepared receipt bound");
    Ok((wire, receipt))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn retain_before_submission(
    network: &Network,
    root: &Path,
    output: &Path,
    command: &norito::json::Value,
    setup_sha: &str,
    registration: &[u8],
    target: &[u8],
    transaction: &SignedTransaction,
    deadline: Instant,
) -> Result<norito::json::Value> {
    require_command(command, "funding")?;
    require_live_campaign(network, root, setup_sha, deadline)?;
    let accepted = read_original(&root.join("funding-accepted.json"), 16 << 10, None)?;
    ensure!(
        norito::json::from_slice::<norito::json::Value>(&accepted)? == *command,
        "accepted funding command differs"
    );
    let (wire, prepared) = prepared(setup_sha, registration, &accepted, target, transaction)?;
    publish(output, "activate-signed.wire", &wire)?;
    File::open(output)?.sync_all()?;
    // Publish the completed receipt atomically only after its exact wire is durable.
    iroha_fs::PrivateDirectory::open_exact(root)?.write_atomic(
        "activation-prepared.json",
        &prepared,
        iroha_fs::PublishMode::CreateNew,
    )?;
    let acknowledgment = wait_command(
        network,
        root,
        "activation-retained",
        setup_sha,
        &hash(&prepared),
        deadline,
    )?;
    let (_, bytes) = selected(&acknowledgment, "retention", 16 << 10)?;
    let receipt: norito::json::Value = norito::json::from_slice(&bytes)?;
    require_retention(&receipt, &wire, transaction.hash().as_ref())?;
    publish(output, "activation-retained.json", &bytes)?;
    File::open(output)?.sync_all()?;
    ensure!(
        read(
            &output.join("activate-signed.wire"),
            ORIGINAL_MAX,
            &hash(&wire)
        )? == transaction.encode_wire_v1()?,
        "retained transaction changed before dispatch"
    );
    require_live_campaign(network, root, setup_sha, deadline)?;
    Ok(norito::json!({
        "prepared_sha256":(hash(&prepared)), "acknowledgment_sha256":(hash(&read_original(&root.join("activation-retained-accepted.json"), 16 << 10, None)?)),
        "retention_sha256":(hash(&bytes)), "signed_wire_sha256":(hash(&wire)),
        "scope":"Exact driver original observed after successful Native retainActivationAttempt; controller DATA, not finality or a physical-device qualification verdict."
    }))
}

#[cfg(test)]
#[path = "activation/tests.rs"]
mod tests;
