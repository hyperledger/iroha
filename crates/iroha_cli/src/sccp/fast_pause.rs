//! Public panel observations and exact account-signed emergency-pause intents.
//!
//! Read responses are advisory preflight. Core rechecks the original draw, current
//! eligibility, live chain identity and `FastHold` head when the instruction executes.

use eyre::{Result, eyre};
use iroha::data_model::{
    NetworkId,
    account::AccountId,
    bridge::SccpNetworkV1,
    isi::{
        InstructionBox,
        sccp::{AcceptSccpPausePanelSeatV1, EndorseSccpFastPauseV1},
    },
    sccp::{
        fast_pause::SccpPausePanelV1,
        governance::{SccpGovernanceBaseRevisionV1, SccpGovernanceSubjectV1},
    },
};
use iroha_sccp::api::{SccpFastPauseViewV1, SccpPauseSeatsV1};

use crate::{Run, RunContext};

/// Standing-panel inspection and public native pause instructions.
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Show the original draw, recorded acceptances and current seat availability.
    Panel,
    /// Accept the explicitly selected standing panel as a drawn member.
    Accept(AcceptArgs),
    /// Endorse one explicitly selected current panel and `FastHold` head.
    Endorse(EndorseArgs),
    /// Show retained rounds, active hold parts, suspensions and panel observations.
    Status,
}

/// Exact standing draw to accept; the account comes from the client configuration.
#[derive(clap::Args, Debug)]
pub struct AcceptArgs {
    /// Nonzero sequence shown by `fast-pause panel`.
    #[arg(long)]
    pub panel_seq: std::num::NonZeroU64,
}

/// Exact replay-protected endorsement selected by the panel member.
#[derive(clap::Args, Debug)]
pub struct EndorseArgs {
    /// External network: ethereum-mainnet, bsc-mainnet or ton-mainnet.
    #[arg(long)]
    pub network: String,
    /// Primary or backup panel identity, as 32-byte hexadecimal.
    #[arg(long)]
    pub panel_id: String,
    /// Current `FastHold` subject revision shown by `governance revisions` (initially zero).
    #[arg(long)]
    pub head: u64,
    /// Nonzero 32-byte hexadecimal digest identifying the public incident.
    #[arg(long)]
    pub incident_digest: String,
}

#[derive(norito::derive::JsonSerialize)]
struct PanelView<'a> {
    panel: Option<&'a SccpPausePanelV1>,
    seats: Option<&'a SccpPauseSeatsV1>,
    eligibility_available: bool,
}

fn acceptance(
    view: &SccpFastPauseViewV1,
    authority: &AccountId,
    panel_seq: u64,
) -> Result<AcceptSccpPausePanelSeatV1> {
    let panel = view
        .panel
        .as_ref()
        .ok_or_else(|| eyre!("no standing pause panel"))?;
    if !panel.has_valid_shape() || panel.panel_seq != panel_seq {
        return Err(eyre!(
            "the selected panel sequence is not the current valid draw"
        ));
    }
    if !panel.drawn.contains(authority) {
        return Err(eyre!("the configured account is not drawn in this panel"));
    }
    if panel.accepted.contains(authority) {
        return Err(eyre!("this account's panel acceptance is already recorded"));
    }
    Ok(AcceptSccpPausePanelSeatV1 { panel_seq })
}

fn endorsement(
    view: &SccpFastPauseViewV1,
    revisions: &[SccpGovernanceBaseRevisionV1],
    authority: &AccountId,
    instruction: EndorseSccpFastPauseV1,
) -> Result<EndorseSccpFastPauseV1> {
    if instruction.network == SccpNetworkV1::SoraTaira || instruction.incident_digest == [0; 32] {
        return Err(eyre!(
            "an endorsement requires an external network and nonzero incident digest"
        ));
    }
    let panel = view
        .panel
        .as_ref()
        .ok_or_else(|| eyre!("no standing pause panel"))?;
    if !panel.has_valid_shape() {
        return Err(eyre!("the peer returned an invalid standing draw"));
    }
    if !view.eligibility_available {
        return Err(eyre!(
            "the authoritative Parliament eligibility source is unavailable"
        ));
    }
    let seats = view
        .seats
        .as_ref()
        .ok_or_else(|| eyre!("current panel seats are unavailable"))?;
    let selected = if instruction.panel_id == panel.primary_id {
        &seats.primary
    } else if instruction.panel_id == panel.backup_id {
        &seats.backup
    } else {
        return Err(eyre!(
            "the selected identity is not a current primary or backup panel"
        ));
    };
    if !selected.contains(authority) || !panel.drawn.contains(authority) {
        return Err(eyre!(
            "the configured account does not hold a seat of the selected panel"
        ));
    }
    let subject = SccpGovernanceSubjectV1::FastHold(instruction.network);
    let head = revisions
        .iter()
        .find(|row| row.subject == subject)
        .map_or(0, |row| row.revision);
    if instruction.head != head {
        return Err(eyre!(
            "the selected FastHold head is stale; review governance revisions"
        ));
    }
    Ok(instruction)
}

impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client = super::blocking(context)?;
        let view = client.sccp().fast_pause()?;
        match self {
            Self::Panel => context.print_data(&PanelView {
                panel: view.panel.as_ref(),
                seats: view.seats.as_ref(),
                eligibility_available: view.eligibility_available,
            }),
            Self::Status => context.print_data(&view),
            Self::Accept(args) => {
                let instruction =
                    acceptance(&view, &context.config().account, args.panel_seq.get())?;
                context.finish(vec![InstructionBox::from(instruction)])
            }
            Self::Endorse(args) => {
                let network_id: NetworkId = context.config().network_id;
                if &client.sccp().capabilities()?.network_id != network_id.as_bytes() {
                    return Err(eyre!(
                        "the peer's network identity differs from the configured chain"
                    ));
                }
                let instruction = endorsement(
                    &view,
                    &client.sccp().governance_revisions()?,
                    &context.config().account,
                    EndorseSccpFastPauseV1 {
                        network_id,
                        network: super::parse_network(&args.network)?,
                        panel_id: super::parse_word(&args.panel_id)?,
                        head: args.head,
                        incident_digest: super::parse_word(&args.incident_digest)?,
                    },
                )?;
                context.finish(vec![InstructionBox::from(instruction)])
            }
        }
    }
}

#[cfg(test)]
mod tests;
