//! The ballot disclosure a voter acknowledges before originating a choice (design §6,
//! integration decision 8).

use iroha_data_model::{
    NetworkId,
    governance::anonymous_ballot::{BallotScopeV1, Digest512},
};

use super::WalletErrorV1;
use crate::context::ScopedBallotContextV1;

/// One statement of the ballot disclosure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DisclosureStatementV1 {
    /// Choices and running counts are public.
    PublicChoicesAndCounts,
    /// The actual roster size is `S`.
    RosterSize,
    /// Small rosters and unanimous results can reveal choices.
    SmallRostersRevealChoices,
    /// The roster size provides no anonymity guarantee.
    NoAnonymityGuarantee,
    /// Network metadata currently remains unprotected.
    NetworkMetadataUnprotected,
}

impl DisclosureStatementV1 {
    /// The five statements, in presentation order.
    pub const ALL: [Self; 5] = [
        Self::PublicChoicesAndCounts,
        Self::RosterSize,
        Self::SmallRostersRevealChoices,
        Self::NoAnonymityGuarantee,
        Self::NetworkMetadataUnprotected,
    ];

    /// A stable code for host interfaces that localize the text.
    pub const fn code(self) -> &'static str {
        match self {
            Self::PublicChoicesAndCounts => "public_choices_and_counts",
            Self::RosterSize => "roster_size",
            Self::SmallRostersRevealChoices => "small_rosters_reveal_choices",
            Self::NoAnonymityGuarantee => "no_anonymity_guarantee",
            Self::NetworkMetadataUnprotected => "network_metadata_unprotected",
        }
    }
}

/// The disclosure of one ballot, bound to its network, scope, policy and roster
/// (`policy_hash`, the list digest `R` and the seat count `S`).
///
/// It is presented before a choice is originated and acknowledged locally; neither it nor
/// its acknowledgement is ever transmitted with a ballot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BallotDisclosureV1 {
    network_id: NetworkId,
    scope: BallotScopeV1,
    policy_hash: Digest512,
    list_digest: Digest512,
    seats: u16,
}

impl BallotDisclosureV1 {
    /// The disclosure of `context`'s ballot.
    pub fn for_context_v1(context: &ScopedBallotContextV1) -> Self {
        Self {
            network_id: *context.network_id(),
            scope: *context.scope(),
            policy_hash: *context.policy_hash(),
            list_digest: *context.list_digest(),
            seats: context.seats(),
        }
    }

    /// The network of the ballot.
    pub fn network_id(&self) -> &NetworkId {
        &self.network_id
    }

    /// The scope of the ballot.
    pub fn scope(&self) -> &BallotScopeV1 {
        &self.scope
    }

    /// `policy_hash` of the ballot.
    pub fn policy_hash(&self) -> &Digest512 {
        &self.policy_hash
    }

    /// The sealed-list digest `R`.
    pub fn list_digest(&self) -> &Digest512 {
        &self.list_digest
    }

    /// The actual roster size `S`.
    pub fn seats(&self) -> u16 {
        self.seats
    }

    /// The English text of `statement` for this ballot.
    pub fn text(&self, statement: DisclosureStatementV1) -> String {
        match statement {
            DisclosureStatementV1::PublicChoicesAndCounts => {
                "Every ballot's choice and the running counts are public.".to_owned()
            }
            DisclosureStatementV1::RosterSize => format!(
                "This ballot's roster has exactly {} sealed seats.",
                self.seats
            ),
            DisclosureStatementV1::SmallRostersRevealChoices => {
                "A small roster or a unanimous result can reveal how individual seats voted."
                    .to_owned()
            }
            DisclosureStatementV1::NoAnonymityGuarantee => {
                "The roster size provides no anonymity guarantee.".to_owned()
            }
            DisclosureStatementV1::NetworkMetadataUnprotected => {
                "Network metadata, such as where a ballot is submitted from, is currently not protected."
                    .to_owned()
            }
        }
    }

    /// The five statements' texts, in presentation order.
    pub fn render(&self) -> Vec<String> {
        DisclosureStatementV1::ALL
            .iter()
            .map(|statement| self.text(*statement))
            .collect()
    }

    /// Whether the disclosure describes `context`'s ballot.
    pub fn matches(&self, context: &ScopedBallotContextV1) -> bool {
        *self == Self::for_context_v1(context)
    }

    /// Record the voter's acknowledgement of exactly the five statements, in presentation
    /// order, as presented by the host interface.
    ///
    /// # Errors
    /// [`WalletErrorV1::IncompleteAcknowledgement`] unless `acknowledged` is exactly
    /// [`DisclosureStatementV1::ALL`].
    pub fn acknowledge(
        self,
        acknowledged: &[DisclosureStatementV1],
    ) -> Result<BallotDisclosureAcknowledgementV1, WalletErrorV1> {
        if acknowledged == DisclosureStatementV1::ALL {
            Ok(BallotDisclosureAcknowledgementV1 { disclosure: self })
        } else {
            Err(WalletErrorV1::IncompleteAcknowledgement)
        }
    }
}

/// The local acknowledgement of one ballot's disclosure. It can only be produced by
/// [`BallotDisclosureV1::acknowledge`], has no codec and is never transmitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BallotDisclosureAcknowledgementV1 {
    disclosure: BallotDisclosureV1,
}

impl BallotDisclosureAcknowledgementV1 {
    /// The acknowledged disclosure.
    pub fn disclosure(&self) -> &BallotDisclosureV1 {
        &self.disclosure
    }

    /// Whether the acknowledgement covers `context`'s ballot: the same network, scope,
    /// policy, list digest and roster size.
    pub fn matches(&self, context: &ScopedBallotContextV1) -> bool {
        self.disclosure.matches(context)
    }
}

#[cfg(test)]
mod tests {
    use iroha_data_model::governance::types::BodyInstanceId;

    use super::*;
    use crate::test_support::scoped_context;

    #[test]
    fn the_disclosure_is_bound_to_the_ballot_and_states_the_roster_size() {
        let context = scoped_context();
        let disclosure = BallotDisclosureV1::for_context_v1(&context);
        assert_eq!(disclosure.network_id(), context.network_id());
        assert_eq!(disclosure.scope(), context.scope());
        assert_eq!(disclosure.policy_hash(), context.policy_hash());
        assert_eq!(disclosure.list_digest(), context.list_digest());
        assert_eq!(disclosure.seats(), 4);
        assert!(disclosure.matches(&context));
        let text = disclosure.render();
        assert_eq!(text.len(), 5);
        assert!(text[1].contains("exactly 4 sealed seats"));
        assert!(text[3].contains("no anonymity guarantee"));
        assert!(text[4].contains("not protected"));
        let codes: std::collections::BTreeSet<_> = DisclosureStatementV1::ALL
            .iter()
            .map(|statement| statement.code())
            .collect();
        assert_eq!(codes.len(), 5);
        let other =
            ScopedBallotContextV1::new(context.context().clone(), BodyInstanceId::new([9; 32]))
                .expect("context");
        assert!(!disclosure.matches(&other));
    }

    #[test]
    fn only_exactly_the_five_statements_acknowledge() {
        let context = scoped_context();
        let disclosure = BallotDisclosureV1::for_context_v1(&context);
        let acknowledgement = disclosure
            .acknowledge(&DisclosureStatementV1::ALL)
            .expect("acknowledged");
        assert!(acknowledgement.matches(&context));
        assert_eq!(acknowledgement.disclosure(), &disclosure);
        let mut reordered = DisclosureStatementV1::ALL;
        reordered.swap(0, 4);
        for partial in [
            &DisclosureStatementV1::ALL[..4],
            &[][..],
            &reordered[..],
            &[DisclosureStatementV1::RosterSize; 5][..],
        ] {
            assert_eq!(
                disclosure.acknowledge(partial),
                Err(WalletErrorV1::IncompleteAcknowledgement)
            );
        }
    }
}
