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
#include "cryptography/public_key.hpp"
#include "cryptography/signed.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "logger/logger.hpp"

// TODO: 2019-03-04 @muratovv refactor std::vector<VoteMessage> with a
// separate class IR-374
auto &getRound(const std::vector<iroha::consensus::yac::VoteMessage> &state) {
  return state.at(0).hash.vote_round;
}

namespace iroha {
  namespace consensus {
    namespace yac {

      std::shared_ptr<Yac> Yac::create(
          YacVoteStorage vote_storage,
          std::shared_ptr<YacNetwork> network,
          std::shared_ptr<YacCryptoProvider> crypto,
          std::shared_ptr<Timer> timer,
          ClusterOrdering order,
          Round round,
          rxcpp::observe_on_one_worker worker,
          logger::LoggerPtr log) {
        return std::make_shared<Yac>(vote_storage,
                                     network,
                                     crypto,
                                     timer,
                                     order,
                                     round,
                                     worker,
                                     std::move(log));
      }

      Yac::Yac(YacVoteStorage vote_storage,
               std::shared_ptr<YacNetwork> network,
               std::shared_ptr<YacCryptoProvider> crypto,
               std::shared_ptr<Timer> timer,
               ClusterOrdering order,
               Round round,
               rxcpp::observe_on_one_worker worker,
               logger::LoggerPtr log)
          : log_(std::move(log)),
            cluster_order_(order),
            round_(round),
            worker_(worker),
            notifier_(worker_, notifier_lifetime_),
            vote_storage_(std::move(vote_storage)),
            network_(std::move(network)),
            crypto_(std::move(crypto)),
            timer_(std::move(timer)) {}

      Yac::~Yac() {
        notifier_lifetime_.unsubscribe();
      }

      // ------|Hash gate|------

      void Yac::vote(YacHash hash,
                     ClusterOrdering order,
                     boost::optional<ClusterOrdering> alternative_order) {
        log_->info("Order for voting: [{}]",
                   boost::algorithm::join(
                       order.getPeers()
                           | boost::adaptors::transformed(
                                 [](const auto &p) { return p->address(); }),
                       ", "));

        std::unique_lock<std::mutex> lock(mutex_);
        cluster_order_ = order;
        alternative_order_ = std::move(alternative_order);
        round_ = hash.vote_round;
        lock.unlock();
        auto vote = crypto_->getVote(hash);
        // TODO 10.06.2018 andrei: IR-1407 move YAC propagation strategy to a
        // separate entity
        votingStep(vote);
      }

      rxcpp::observable<Answer> Yac::onOutcome() {
        return notifier_.get_observable();
      }

      // ------|Network notifications|------

      template <typename T, typename P>
      void removeMatching(std::vector<T> &target, const P &predicate) {
        target.erase(std::remove_if(target.begin(), target.end(), predicate),
                     target.end());
      }

      template <typename CollectionType, typename ElementType>
      bool contains(const CollectionType &haystack, const ElementType &needle) {
        return std::find(haystack.begin(), haystack.end(), needle)
            != haystack.end();
      }

      /// moves the votes not present in known_keys from votes to return value
      void Yac::removeUnknownPeersVotes(std::vector<VoteMessage> &votes,
                                        ClusterOrdering &order) {
        auto known_keys = order.getPeers()
            | boost::adaptors::transformed(
                              [](const auto &peer) { return peer->pubkey(); });
        removeMatching(
            votes,
            [known_keys = std::move(known_keys), this](VoteMessage &vote) {
              if (not contains(known_keys, vote.signature->publicKey())) {
                log_->warn("Got a vote from an unknown peer: {}", vote);
                return true;
              }
              return false;
            });
      }

      void Yac::onState(std::vector<VoteMessage> state) {
        std::unique_lock<std::mutex> guard(mutex_);

        removeUnknownPeersVotes(state, getCurrentOrder());
        if (state.empty()) {
          log_->debug("No votes left in the message.");
          return;
        }

        if (crypto_->verify(state)) {
          auto &proposal_round = getRound(state);

          if (proposal_round.block_round > round_.block_round) {
            guard.unlock();
            log_->info("Pass state from future for {} to pipeline",
                       proposal_round);
            notifier_.get_subscriber().on_next(FutureMessage{std::move(state)});
            return;
          }

          if (proposal_round.block_round < round_.block_round) {
            log_->info("Received state from past for {}, try to propagate back",
                       proposal_round);
            tryPropagateBack(state);
            guard.unlock();
            return;
          }

          if (alternative_order_) {
            // filter votes with peers from cluster order to avoid the case when
            // alternative peer is not present in cluster order
            removeUnknownPeersVotes(state, cluster_order_);
            if (state.empty()) {
              log_->debug("No votes left in the message.");
              return;
            }
          }

          applyState(state, guard);
        } else {
          log_->warn(
              "Crypto verification failed for message. Votes: [{}]",
              boost::algorithm::join(
                  state | boost::adaptors::transformed([](const auto &v) {
                    return v.signature->toString();
                  }),
                  ", "));
        }
      }

      // ------|Private interface|------

      void Yac::votingStep(VoteMessage vote) {
        std::unique_lock<std::mutex> lock(mutex_);

        auto committed = vote_storage_.isCommitted(vote.hash.vote_round);
        if (committed) {
          return;
        }

        auto &cluster_order = getCurrentOrder();

        const auto &current_leader = cluster_order.currentLeader();

        log_->info("Vote {} to peer {}", vote, current_leader);

        network_->sendState(current_leader, {vote});
        cluster_order.switchToNext();
        auto has_next = cluster_order.hasNext();
        lock.unlock();
        if (has_next) {
          timer_->invokeAfterDelay([this, vote] { this->votingStep(vote); });
        }
      }

      void Yac::closeRound() {
        timer_->deny();
      }

      ClusterOrdering &Yac::getCurrentOrder() {
        return alternative_order_ ? *alternative_order_ : cluster_order_;
      }

      boost::optional<std::shared_ptr<shared_model::interface::Peer>>
      Yac::findPeer(const VoteMessage &vote) {
        auto peers = cluster_order_.getPeers();
        auto it =
            std::find_if(peers.begin(), peers.end(), [&](const auto &peer) {
              return peer->pubkey() == vote.signature->publicKey();
            });
        return it != peers.end() ? boost::make_optional(std::move(*it))
                                 : boost::none;
      }

      // ------|Apply data|------

      void Yac::applyState(const std::vector<VoteMessage> &state,
                           std::unique_lock<std::mutex> &lock) {
        assert(lock.owns_lock());
        auto answer =
            vote_storage_.store(state, cluster_order_.getNumberOfPeers());

        // TODO 10.06.2018 andrei: IR-1407 move YAC propagation strategy to a
        // separate entity

        iroha::match_in_place(
            answer,
            [&](const auto &answer) {
              auto &proposal_round = getRound(state);

              /*
               * It is possible that a new peer with an outdated peers list may
               * collect an outcome from a smaller number of peers which are
               * included in set of `f` peers in the system. The new peer will
               * not accept our message with valid supermajority because he
               * cannot apply votes from unknown peers.
               */
              if (state.size() > 1) {
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

              auto processing_state =
                  vote_storage_.getProcessingState(proposal_round);

              auto votes = [](const auto &state) { return state.votes; };

              auto current_round = round_;
              switch (processing_state) {
                case ProposalState::kNotSentNotProcessed:
                  vote_storage_.nextProcessingState(proposal_round);
                  log_->info("Propagate state {} to whole network",
                             proposal_round);
                  this->propagateState(visit_in_place(answer, votes));
                  break;
                case ProposalState::kSentNotProcessed:
                  vote_storage_.nextProcessingState(proposal_round);
                  log_->info("Pass outcome for {} to pipeline", proposal_round);
                  lock.unlock();
                  if (proposal_round >= current_round) {
                    this->closeRound();
                  }
                  notifier_.get_subscriber().on_next(answer);
                  break;
                case ProposalState::kSentProcessed:
                  this->tryPropagateBack(state);
                  break;
              }
            },
            // sent a state which didn't match with current one
            [&]() { this->tryPropagateBack(state); });
        if (lock.owns_lock()) {
          lock.unlock();
        }
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
                log_->info("Propagate state {} directly to {}",
                           last_round,
                           from->address());
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
        for (const auto &peer : cluster_order_.getPeers()) {
          propagateStateDirectly(*peer, msg);
        }
      }

      void Yac::propagateStateDirectly(const shared_model::interface::Peer &to,
                                       const std::vector<VoteMessage> &msg) {
        network_->sendState(to, msg);
      }

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
