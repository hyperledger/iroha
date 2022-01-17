/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/yac.hpp"

#include <utility>

#include <boost/algorithm/string/join.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include "common/bind.hpp"
#include "common/visitor.hpp"
#include "consensus/yac/cluster_order.hpp"
#include "consensus/yac/storage/yac_proposal_storage.hpp"
#include "consensus/yac/timer.hpp"
#include "consensus/yac/yac_crypto_provider.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "logger/logger.hpp"

// TODO: 2019-03-04 @muratovv refactor std::vector<VoteMessage> with a
// separate class IR-374
auto &getRound(const std::vector<iroha::consensus::yac::VoteMessage> &state) {
  return state.at(0).hash.vote_round;
}

using iroha::consensus::yac::Yac;

std::shared_ptr<Yac> Yac::create(YacVoteStorage vote_storage,
                                 std::shared_ptr<YacNetwork> network,
                                 std::shared_ptr<YacCryptoProvider> crypto,
                                 std::shared_ptr<Timer> timer,
                                 shared_model::interface::types::PeerList order,
                                 Round round,
                                 logger::LoggerPtr log) {
  return std::make_shared<Yac>(
      vote_storage, network, crypto, timer, order, round, std::move(log));
}

Yac::Yac(YacVoteStorage vote_storage,
         std::shared_ptr<YacNetwork> network,
         std::shared_ptr<YacCryptoProvider> crypto,
         std::shared_ptr<Timer> timer,
         shared_model::interface::types::PeerList order,
         Round round,
         logger::LoggerPtr log)
    : log_(std::move(log)),
      cluster_order_(order),
      round_(round),
      vote_storage_(std::move(vote_storage)),
      network_(std::move(network)),
      crypto_(std::move(crypto)),
      timer_(std::move(timer)) {}

void Yac::stop() {
  network_->stop();
}

std::optional<iroha::consensus::yac::Answer> Yac::processRoundSwitch(
    consensus::Round const &round,
    shared_model::interface::types::PeerList const &peers,
    shared_model::interface::types::PeerList const &sync_peers) {
  round_ = round;
  cluster_order_ = peers;
  syncing_peers_ = sync_peers;
  std::optional<iroha::consensus::yac::Answer> result;
  auto it = future_states_.lower_bound(round_);
  while (it != future_states_.end()
         and it->first.block_round == round_.block_round) {
    if (not it->second.empty()) {
      if (auto maybe_answer = onState(std::vector<VoteMessage>(
              std::make_move_iterator(it->second.begin()),
              std::make_move_iterator(it->second.end())))) {
        result = std::move(maybe_answer);
      }
    }
    ++it;
  }
  future_states_.erase(future_states_.begin(), it);
  return result;
}

// ------|Hash gate|------

void Yac::vote(YacHash hash,
               ClusterOrdering order,
               std::optional<ClusterOrdering> alternative_order) {
  log_->info(
      "Order for voting: [{}]",
      boost::algorithm::join(
          order.getPeers() | boost::adaptors::transformed([](const auto &p) {
            return p->address();
          }),
          ", "));

  alternative_order_.reset();
  if (alternative_order) {
    alternative_order_ = alternative_order->getPeers();
  }
  assert(round_ == hash.vote_round);
  auto vote = crypto_->getVote(hash);
  // TODO 10.06.2018 andrei: IR-1407 move YAC propagation strategy to a
  // separate entity
  votingStep(vote, alternative_order ? *alternative_order : order);
}

// ------|Network notifications|------

template <typename T, typename P>
void removeMatching(std::vector<T> &target, const P &predicate) {
  target.erase(std::remove_if(target.begin(), target.end(), predicate),
               target.end());
}

template <typename CollectionType, typename ElementType>
bool contains(const CollectionType &haystack, const ElementType &needle) {
  return std::find(haystack.begin(), haystack.end(), needle) != haystack.end();
}

/// moves the votes not present in known_keys from votes to return value
void Yac::removeUnknownPeersVotes(
    std::vector<VoteMessage> &votes,
    shared_model::interface::types::PeerList const &peers) {
  auto known_keys = peers | boost::adaptors::transformed([](const auto &peer) {
                      return peer->pubkey();
                    });
  removeMatching(votes,
                 [known_keys = std::move(known_keys), this](VoteMessage &vote) {
                   if (not contains(known_keys, vote.signature->publicKey())) {
                     log_->warn("Got a vote from an unknown peer: {}", vote);
                     return true;
                   }
                   return false;
                 });
}

std::optional<iroha::consensus::yac::Answer> Yac::onState(
    std::vector<VoteMessage> state) {
  removeUnknownPeersVotes(state, getCurrentOrder());
  if (state.empty()) {
    log_->debug("No votes left in the message.");
    return std::nullopt;
  }

  if (crypto_->verify(state)) {
    auto &proposal_round = getRound(state);

    if (proposal_round.block_round > round_.block_round) {
      log_->info("Pass state from future for {} to pipeline", proposal_round);
      future_states_[proposal_round].insert(state.begin(), state.end());
      return FutureMessage{std::move(state)};
    }

    if (proposal_round < round_) {
      log_->info("Received state from past for {}, try to propagate back",
                 proposal_round);
      tryPropagateBack(state);
      return std::nullopt;
    }

    if (alternative_order_) {
      // filter votes with peers from cluster order to avoid the case when
      // alternative peer is not present in cluster order
      removeUnknownPeersVotes(state, cluster_order_);
      if (state.empty()) {
        log_->debug("No votes left in the message.");
        return std::nullopt;
      }
    }

    return applyState(state);
  }

  log_->warn("Crypto verification failed for message. Votes: [{}]",
             boost::algorithm::join(
                 state | boost::adaptors::transformed([](const auto &v) {
                   return v.signature->toString();
                 }),
                 ", "));
  return std::nullopt;
}

// ------|Private interface|------

void Yac::votingStep(VoteMessage vote,
                     ClusterOrdering order,
                     uint32_t attempt) {
  log_->info("votingStep got vote: {}, attempt {}", vote, attempt);

  auto committed = vote_storage_.isCommitted(vote.hash.vote_round);
  if (committed) {
    return;
  }

  const auto &current_leader = order.currentLeader();
  log_->info("Vote {} to peer {}", vote, current_leader);

  propagateStateDirectly(current_leader, {vote});
  order.switchToNext();

  timer_->invokeAfterDelay([this, vote, order(std::move(order)), attempt] {
    this->votingStep(vote, std::move(order), attempt + 1);
  });
}

shared_model::interface::types::PeerList &Yac::getCurrentOrder() {
  return alternative_order_ ? *alternative_order_ : cluster_order_;
}

std::optional<std::shared_ptr<shared_model::interface::Peer>> Yac::findPeer(
    const VoteMessage &vote) {
  auto it = std::find_if(
      cluster_order_.begin(), cluster_order_.end(), [&](const auto &peer) {
        return peer->pubkey() == vote.signature->publicKey();
      });
  return it != cluster_order_.end() ? std::make_optional(*it) : std::nullopt;
}

// ------|Apply data|------

std::optional<iroha::consensus::yac::Answer> Yac::applyState(
    const std::vector<VoteMessage> &state) {
  auto answer = vote_storage_.store(state, cluster_order_.size());

  // TODO 10.06.2018 andrei: IR-1407 move YAC propagation strategy to a
  // separate entity

  if (answer) {
    auto &proposal_round = getRound(state);
    auto current_round = round_;

    /*
     * It is possible that a new peer with an outdated peers list may
     * collect an outcome from a smaller number of peers which are
     * included in set of `f` peers in the system. The new peer will
     * not accept our message with valid supermajority because he
     * cannot apply votes from unknown peers.
     */
    if (state.size() > 1 or cluster_order_.size() == 1) {
      // some peer has already collected commit/reject, so it is sent
      if (vote_storage_.getProcessingState(proposal_round)
          == ProposalState::kNotSentNotProcessed) {
        vote_storage_.nextProcessingState(proposal_round);
        log_->info(
            "Received supermajority of votes for {}, skip "
            "propagation",
            proposal_round);
      }
    }

    auto processing_state = vote_storage_.getProcessingState(proposal_round);

    auto votes = [](const auto &state) -> const std::vector<VoteMessage> & {
      return state.votes;
    };

    switch (processing_state) {
      case ProposalState::kNotSentNotProcessed:
        vote_storage_.nextProcessingState(proposal_round);
        log_->info("Propagate state {} to whole network", proposal_round);
        propagateState(visit_in_place(*answer, votes));
        break;
      case ProposalState::kSentNotProcessed:
        vote_storage_.nextProcessingState(proposal_round);
        log_->info("Pass outcome for {} to pipeline", proposal_round);
        return *answer;
      case ProposalState::kSentProcessed:
        if (current_round > proposal_round)
          tryPropagateBack(state);
        break;
    }
  }
  return std::nullopt;
}

void Yac::tryPropagateBack(const std::vector<VoteMessage> &state) {
  // yac back propagation will work only if another peer is in
  // propagation stage because if peer sends list of votes this means that
  // state is already committed
  if (state.size() != 1) {
    return;
  }

  vote_storage_.getLastFinalizedRound() | [&](const auto &last_round) {
    if (getRound(state) <= last_round) {
      vote_storage_.getState(last_round) | [&](const auto &last_state) {
        this->findPeer(state.at(0)) | [&](const auto &from) {
          log_->info(
              "Propagate state {} directly to {}", last_round, from->address());
          auto votes = [](const auto &state) { return state.votes; };
          this->propagateStateDirectly(*from,
                                       visit_in_place(last_state, votes));
        };
      };
    }
  };
}

// ------|Propagation|------

void Yac::propagateState(const std::vector<VoteMessage> &msg) {
  for (const auto &peer : cluster_order_) propagateStateDirectly(*peer, msg);

  for (const auto &peer : syncing_peers_) propagateStateDirectly(*peer, msg);
}

void Yac::propagateStateDirectly(const shared_model::interface::Peer &to,
                                 const std::vector<VoteMessage> &msg) {
  network_->sendState(to, msg);
}
