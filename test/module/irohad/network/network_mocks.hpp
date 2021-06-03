/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_NETWORK_MOCKS_HPP
#define IROHA_NETWORK_MOCKS_HPP

#include <gmock/gmock.h>

#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "network/block_loader.hpp"
#include "network/consensus_gate.hpp"
#include "network/ordering_gate.hpp"
#include "network/peer_communication_service.hpp"
#include "simulator/block_creator_common.hpp"

namespace shared_model {
  namespace interface {
    class Transaction;
  }
}  // namespace shared_model

namespace iroha {
  namespace network {
    class MockPeerCommunicationService : public PeerCommunicationService {
     public:
      MOCK_CONST_METHOD1(
          propagate_transaction,
          void(std::shared_ptr<const shared_model::interface::Transaction>));

      MOCK_CONST_METHOD1(
          propagate_batch,
          void(std::shared_ptr<shared_model::interface::TransactionBatch>));
    };

    class MockBlockLoader : public BlockLoader {
     public:
      MOCK_METHOD2(
          retrieveBlocks,
          iroha::expected::Result<std::unique_ptr<BlockReader>, std::string>(
              const shared_model::interface::types::HeightType,
              shared_model::interface::types::PublicKeyHexStringView));
      MOCK_METHOD2(retrieveBlock,
                   iroha::expected::Result<
                       std::unique_ptr<shared_model::interface::Block>,
                       std::string>(
                       shared_model::interface::types::PublicKeyHexStringView,
                       shared_model::interface::types::HeightType));
    };

    class MockOrderingGate : public OrderingGate {
     public:
      MOCK_CONST_METHOD1(
          propagateTransaction,
          void(std::shared_ptr<const shared_model::interface::Transaction>
                   transaction));

      MOCK_METHOD1(
          propagateBatch,
          void(std::shared_ptr<shared_model::interface::TransactionBatch>));

      MOCK_METHOD1(setPcs, void(const PeerCommunicationService &));

      MOCK_METHOD0(stop, void());
    };

    class MockConsensusGate : public ConsensusGate {
     public:
      MOCK_METHOD1(vote, void(const simulator::BlockCreatorEvent &));

      MOCK_METHOD0(stop, void());
    };

  }  // namespace network
}  // namespace iroha

#endif  // IROHA_NETWORK_MOCKS_HPP
