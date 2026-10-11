#![allow(clippy::redundant_pub_crate, clippy::needless_pass_by_value)]
use super::commands::{DiagnosticsArgs, LanesArgs, ParamsArgs, StatusArgs};
use crate::{CliOutputFormat, RunContext};
use eyre::Result;
use norito::json::Value;
pub(crate) fn status<C: RunContext>(context: &mut C, _args: StatusArgs) -> Result<()> {
    let client = context.client_from_config()?;
    let value = client.get_sumeragi_status_json()?;
    match context.output_format() {
        CliOutputFormat::Text => context.println(summarize_status(&value)),
        CliOutputFormat::Json => context.print_data(&value),
    }
}
pub(crate) fn lanes<C: RunContext>(context: &mut C, args: LanesArgs) -> Result<()> {
    context.operator_key_pair().ok_or_else(|| {
        eyre::eyre!(
            "consensus lanes require --operator-private-key-file or --operator-private-key-fd"
        )
    })?;
    let mut client = context.client_from_config()?;
    if let Some(torii_url) = args.torii_url {
        let mut builder = client.to_builder();
        builder.torii_url = torii_url;
        client = builder.build()?;
    }
    let lanes = client.get_sumeragi_lanes()?;
    context.print_data(&lanes)
}
pub(crate) fn diagnostics<C: RunContext>(context: &mut C, _args: DiagnosticsArgs) -> Result<()> {
    let client = context.client_from_config()?;
    let operator_key = context
        .operator_key_pair()
        .cloned()
        .ok_or_else(|| eyre::eyre!("consensus diagnostics require --operator-private-key-file"))?;
    let operator =
        iroha::blocking::OperatorClient::from_client(client.operator_client(operator_key)?)?;
    let diagnostics = operator.consensus().diagnostics()?;
    let value = norito::json::to_value(&diagnostics)?;
    match context.output_format() {
        CliOutputFormat::Text => context.println(summarize_diagnostics(&value)),
        CliOutputFormat::Json => context.print_data(&value),
    }
}
pub(crate) fn params<C: RunContext>(context: &mut C, _args: ParamsArgs) -> Result<()> {
    let client = context.client_from_config()?;
    let value = client.get_sumeragi_params_json()?;
    match context.output_format() {
        CliOutputFormat::Text => context.println(summarize_params(&value)),
        CliOutputFormat::Json => context.print_data(&value),
    }
}
/// One line from the `/v1/sumeragi/status` JSON (`iroha_data_model::sumeragi::SumeragiStatus`).
fn summarize_status(value: &Value) -> String {
    let number = |key: &str| value.get(key).and_then(Value::as_u64).unwrap_or(0);
    let flag = |key: &str| value.get(key).and_then(Value::as_bool).unwrap_or(false);
    let key = |key: &str| value.get(key).and_then(Value::as_str).unwrap_or("-");
    let lock = value
        .get("high_qc_view")
        .and_then(Value::as_u64)
        .map_or_else(|| "-".to_owned(), |view| view.to_string());
    let halted = match value.get("halted") {
        None | Some(Value::Null) => "no".to_owned(),
        Some(reason) => reason.as_str().map_or_else(
            || norito::json::to_json(reason).unwrap_or_default(),
            str::to_owned,
        ),
    };
    format!(
        "height={} view={} stage={} leader={} proxy_tail={} lock_view={lock} committed={} applied={} awaiting={} signing={} halted={halted}",
        number("height"),
        number("view"),
        number("stage"),
        key("leader"),
        key("proxy_tail"),
        number("committed_height"),
        number("applied_height"),
        flag("awaiting"),
        !value.get("signer").is_none_or(Value::is_null)
            && !flag("abstaining")
            && !flag("unanchored"),
    )
}
fn summarize_diagnostics(value: &Value) -> String {
    let depth = value
        .get("tx_queue_depth")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let capacity = value
        .get("tx_queue_capacity")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let saturated = value
        .get("tx_queue_saturated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let governance_lanes = value
        .get("lane_governance")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let sealed = value
        .get("lane_governance_sealed_total")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let npos = value.get("npos").and_then(Value::as_object);
    let election = npos.map_or_else(
        || "permissioned".to_owned(),
        |npos| {
            let epoch = npos
                .get("epoch_length_blocks")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            format!("npos(epoch={epoch})")
        },
    );
    format!(
        "queue={depth}/{capacity} saturated={saturated} election={election} governance_lanes={governance_lanes} sealed={sealed}"
    )
}
fn summarize_params(value: &Value) -> String {
    let cadence = value
        .get("block_cadence_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let drift = value
        .get("max_clock_drift_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let height = value
        .get("chain_height")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    format!("block_cadence={cadence}ms max_clock_drift={drift}ms chain_height={height}")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn summarize_status_reports_the_round_and_heights() {
        let value = norito::json!({
            "height": 7,
            "view": 3,
            "stage": 1,
            "leader": "ea01leader",
            "proxy_tail": "ea01tail",
            "high_qc_view": 2,
            "committed_height": 6,
            "applied_height": 6,
            "awaiting": false,
            "signer": "ea01me",
            "unanchored": false,
            "abstaining": false,
            "halted": null
        });
        assert_eq!(
            summarize_status(&value),
            "height=7 view=3 stage=1 leader=ea01leader proxy_tail=ea01tail lock_view=2 committed=6 applied=6 awaiting=false signing=true halted=no"
        );
        let observer = norito::json!({ "height": 1, "signer": null, "halted": "DriverAnomaly" });
        assert_eq!(
            summarize_status(&observer),
            "height=1 view=0 stage=0 leader=- proxy_tail=- lock_view=- committed=0 applied=0 awaiting=false signing=false halted=DriverAnomaly"
        );
    }
    #[test]
    fn summarize_diagnostics_keeps_operator_state_separate() {
        let value = norito::json!({
            "tx_queue_depth": 4,
            "tx_queue_capacity": 10,
            "tx_queue_saturated": false,
            "npos": {
                "epoch_length_blocks": 100
            },
            "lane_governance": [{ "lane_id": 1 }],
            "lane_governance_sealed_total": 0
        });
        assert_eq!(
            summarize_diagnostics(&value),
            "queue=4/10 saturated=false election=npos(epoch=100) governance_lanes=1 sealed=0"
        );
    }
    #[test]
    fn summarize_params_reports_signed_cadence_and_height() {
        let value = norito::json!({
            "block_cadence_ms": 1000,
            "max_clock_drift_ms": 500,
            "chain_height": 42
        });
        assert_eq!(
            summarize_params(&value),
            "block_cadence=1000ms max_clock_drift=500ms chain_height=42"
        );
    }
}
