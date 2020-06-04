/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/integration_framework/fake_peer/behaviour/behaviour.hpp"

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
        std::weak_ptr<Behaviour> weak_behaviour_;
        std::weak_ptr<FakePeer> weak_fake_peer_;

       public:
        using Protected =
            std::tuple<std::shared_ptr<Behaviour>, std::shared_ptr<FakePeer>>;

        Locker(std::weak_ptr<Behaviour> weak_behaviour,
               std::weak_ptr<FakePeer> weak_fake_peer)
            : weak_behaviour_(std::move(weak_behaviour)),
              weak_fake_peer_(std::move(weak_fake_peer)) {}

        boost::optional<Protected> protect() const {
          Protected p{weak_behaviour_.lock(), weak_fake_peer_.lock()};
          return boost::make_optional(std::get<0>(p) and std::get<1>(p), p);
        }
      };
      Locker locker(shared_from_this(), fake_peer);

      // subscribe for all messages
      subscriptions_.emplace_back(
          getFakePeer().value()->getMstStatesObservable().subscribe(
              [this, locker](const auto &message) {
                if (auto protector = locker.protect()) {
                  this->processMstMessage(message);
                }
              }));
      subscriptions_.emplace_back(
          getFakePeer().value()->getYacStatesObservable().subscribe(
              [this, locker](const auto &message) {
                if (auto protector = locker.protect()) {
                  this->processYacMessage(message);
                }
              }));
      subscriptions_.emplace_back(
          getFakePeer().value()->getOsBatchesObservable().subscribe(
              [this, locker](const auto &batch) {
                if (auto protector = locker.protect()) {
                  this->processOsBatch(batch);
                }
              }));
      subscriptions_.emplace_back(
          getFakePeer().value()->getOgProposalsObservable().subscribe(
              [this, locker](const auto &proposal) {
                if (auto protector = locker.protect()) {
                  this->processOgProposal(proposal);
                }
              }));
      subscriptions_.emplace_back(
          getFakePeer().value()->getBatchesObservable().subscribe(
              [this, locker](const auto &batches) {
                if (auto protector = locker.protect()) {
                  this->processOrderingBatches(*batches);
                }
              }));
    }

    void Behaviour::absolve() {
      for (auto &subscription : subscriptions_) {
        subscription.unsubscribe();
      }
      fake_peer_wptr_.reset();
    }

    std::optional<std::reference_wrapper<FakePeer>> Behaviour::getFakePeer() {
      auto fake_peer = fake_peer_wptr_.lock();
      if (fake_peer) {
        return *fake_peer;
      }
      return std::nullopt;
    }

    logger::LoggerPtr &Behaviour::getLogger() {
      return log_;
    }

  }  // namespace fake_peer
}  // namespace integration_framework
