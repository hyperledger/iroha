/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INTEGRATION_FRAMEWORK_FAKE_PEER_TYPES_HPP_
#define INTEGRATION_FRAMEWORK_FAKE_PEER_TYPES_HPP_

#include <functional>
#include <memory>
#include <vector>

#include <boost/optional.hpp>
#include <boost/range/any_range.hpp>
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace crypto {
    class Keypair;
    class Hash;
  }  // namespace crypto
  namespace interface {
    class CommonObjectsFactory;
    class Proposal;
    class Transaction;
    class TransactionBatch;
    class TransactionBatchParser;
    class TransactionBatchFactory;
  }  // namespace interface
  namespace proto {
    class Block;
    class Proposal;
  }  // namespace proto
}  // namespace shared_model

namespace iroha {
  namespace ametsuchi {
    class TxPresenceCache;
  }  // namespace ametsuchi
  namespace protocol {
    class Transaction;
  }
  namespace consensus {
    namespace yac {
      class NetworkImpl;
      class YacCryptoProvider;
      class YacHash;
      struct VoteMessage;
    }  // namespace yac
    struct Round;
  }  // namespace consensus
  namespace ordering {
    namespace transport {
      class OnDemandOsServerGrpc;
    }
    class OrderingGateTransportGrpc;
    class OrderingServiceTransportGrpc;
  }  // namespace ordering
  class MstState;
}  // namespace iroha

namespace integration_framework {
  namespace fake_peer {
    class Behaviour;
    class BlockStorage;
    class ProposalStorage;
    class FakePeer;
    class LoaderGrpc;
    class MstNetworkNotifier;
    class OgNetworkNotifier;
    class OsNetworkNotifier;
    class OnDemandOsNetworkNotifier;
    class YacNetworkNotifier;
    struct MstMessage;

    using YacMessage = std::vector<iroha::consensus::yac::VoteMessage>;
    using LoaderBlockRequest = shared_model::interface::types::HeightType;
    using LoaderBlocksRequest = shared_model::interface::types::HeightType;
    using LoaderBlockRequestResult =
        boost::optional<std::shared_ptr<const shared_model::proto::Block>>;
    using LoaderBlocksRequestResult =
        boost::any_range<std::shared_ptr<const shared_model::proto::Block>,
                         boost::single_pass_traversal_tag>;
    using OrderingProposalRequest = iroha::consensus::Round;
    using OrderingProposalRequestResult =
        boost::optional<std::shared_ptr<const shared_model::proto::Proposal>>;
    using BatchesCollection =
        std::vector<std::shared_ptr<shared_model::interface::TransactionBatch>>;

  }  // namespace fake_peer
}  // namespace integration_framework

#endif /* INTEGRATION_FRAMEWORK_FAKE_PEER_TYPES_HPP_ */
