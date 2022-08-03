/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/integration_framework/fake_peer/behaviour/behaviour.hpp"

#include "common/bind.hpp"
#include "logger/logger.hpp"

namespace integration_framework {
  namespace fake_peer {

    Behaviour::~Behaviour() {
      absolve();
    }

    void Behaviour::setup(const std::shared_ptr<FakePeer> &fake_peer,
                          logger::LoggerPtr log) {
      // This code feels like part of constructor, but the use of `this'
      // to call virtual functions from base class constructor seems wrong.
      // Hint: such calls would precede the derived class construction.
      fake_peer_wptr_ = fake_peer;
      log_ = std::move(log);

      // Stores weak pointers. Tries to lock them at once.
      class Locker {
        std::weak_ptr<Behaviour> behaviour_;
        rxcpp::composite_subscription subscription_;

       public:
        Locker(std::weak_ptr<Behaviour> behaviour,
               rxcpp::composite_subscription subscription)
            : behaviour_(std::move(behaviour)),
              subscription_(std::move(subscription)) {}

        std::optional<std::shared_ptr<Behaviour>> protect() const {
          if (auto behaviour = behaviour_.lock()) {
            return behaviour;
          } else {
            subscription_.unsubscribe();
            return std::nullopt;
          }
        }
      };

      rxcpp::composite_subscription subscription;
      Locker locker(weak_from_this(), subscription);

      using iroha::operator|;

      // subscribe for all messages
      fake_peer->getYacStatesObservable().subscribe(
          subscription,
          [locker](std::shared_ptr<const YacMessage> const &message) {
            locker.protect() |
                [&](auto protector) { protector->processYacMessage(message); };
          });
      fake_peer->getOsBatchesObservable().subscribe(
          subscription,
          [locker](
              std::shared_ptr<shared_model::interface::TransactionBatch> const
                  &batch) {
            locker.protect() |
                [&](auto protector) { protector->processOsBatch(batch); };
          });
      fake_peer->getOgProposalsObservable().subscribe(
          subscription,
          [locker](std::shared_ptr<shared_model::interface::Proposal> const
                       &proposal) {
            locker.protect() |
                [&](auto protector) { protector->processOgProposal(proposal); };
          });
      fake_peer->getBatchesObservable().subscribe(
          subscription,
          [locker](std::shared_ptr<BatchesCollection> const &batches) {
            locker.protect() | [&](auto protector) {
              protector->processOrderingBatches(*batches);
            };
          });
    }

    void Behaviour::absolve() {
      fake_peer_wptr_.reset();
    }

    std::optional<std::shared_ptr<FakePeer>> Behaviour::getFakePeer() {
      auto fake_peer = fake_peer_wptr_.lock();
      if (fake_peer) {
        return fake_peer;
      }
      return std::nullopt;
    }

    logger::LoggerPtr &Behaviour::getLogger() {
      return log_;
    }

  }  // namespace fake_peer
}  // namespace integration_framework
