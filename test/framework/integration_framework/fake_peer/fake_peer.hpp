/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INTEGRATION_FRAMEWORK_FAKE_PEER_HPP_
#define INTEGRATION_FRAMEWORK_FAKE_PEER_HPP_

#include <memory>
#include <string>

#include <boost/core/noncopyable.hpp>
#include <rxcpp/rx.hpp>
#include "framework/integration_framework/fake_peer/network/mst_message.hpp"
#include "framework/integration_framework/fake_peer/proposal_storage.hpp"
#include "framework/integration_framework/fake_peer/types.hpp"
#include "interfaces/iroha_internal/abstract_transport_factory.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"
#include "network/impl/async_grpc_client.hpp"
#include "ordering/impl/on_demand_os_client_grpc.hpp"

class ServerRunner;

namespace integration_framework {
  namespace fake_peer {

    /**
     * A lightweight implementation of iroha peer network interface for
     * inter-peer communications testing.
     */
    class FakePeer final : public boost::noncopyable,
                           public std::enable_shared_from_this<FakePeer> {
     public:
      using TransportFactoryType =
          shared_model::interface::AbstractTransportFactory<
              shared_model::interface::Transaction,
              iroha::protocol::Transaction>;

      /**
       * Constructor.
       *
       * @param listen_ip - IP on which this fake peer should listen
       * @param internal_port - the port for internal commulications
       * @param key - the keypair of this peer
       * @param real_peer - the main tested peer managed by ITF
       * @param common_objects_factory - common_objects_factory
       * @param transaction_factory - transaction_factory
       * @param batch_parser - batch_parser
       * @param transaction_batch_factory - transaction batch factory
       * @param proposal_factory - proposal factory
       * @param tx_presence_cache - for MST transport
       * @param log_manager - log manager
       */
      FakePeer(
          const std::string &listen_ip,
          size_t internal_port,
          const boost::optional<shared_model::crypto::Keypair> &key,
          std::shared_ptr<shared_model::interface::Peer> real_peer,
          const std::shared_ptr<shared_model::interface::CommonObjectsFactory>
              &common_objects_factory,
          std::shared_ptr<TransportFactoryType> transaction_factory,
          std::shared_ptr<shared_model::interface::TransactionBatchParser>
              batch_parser,
          std::shared_ptr<shared_model::interface::TransactionBatchFactory>
              transaction_batch_factory,
          std::shared_ptr<iroha::ordering::transport::OnDemandOsClientGrpc::
                              TransportFactoryType> proposal_factory,
          std::shared_ptr<iroha::ametsuchi::TxPresenceCache> tx_presence_cache,
          logger::LoggerManagerTreePtr log_manager);

      ~FakePeer();

      /// Initialization method.
      /// \attention Must be called prior to any other instance method (except
      /// for constructor).
      FakePeer &initialize();

      /// Assign the given behaviour to this fake peer.
      FakePeer &setBehaviour(const std::shared_ptr<Behaviour> &behaviour);

      /// Get the behaviour assigned to this peer, if any, otherwise nullptr.
      std::shared_ptr<Behaviour> getBehaviour() const;

      /// Assign this peer a block storage. Used by behaviours.
      FakePeer &setBlockStorage(
          const std::shared_ptr<BlockStorage> &block_storage);

      /// Remove any block storage previously assigned to this peer, if any.
      FakePeer &removeBlockStorage();

      /// Get the block storage previously assigned to this peer, if any.
      boost::optional<const BlockStorage &> getBlockStorage() const;

      ProposalStorage &getProposalStorage();

      /// Start the fake peer.
      std::unique_ptr<ServerRunner> run();

      /// Get the address:port string of this peer.
      std::string getAddress() const;

      /// Get the keypair of this peer.
      const shared_model::crypto::Keypair &getKeypair() const;

      /// Get the observable of MST states received by this peer.
      rxcpp::observable<std::shared_ptr<MstMessage>> getMstStatesObservable();

      /// Get the observable of YAC states received by this peer.
      rxcpp::observable<std::shared_ptr<const YacMessage>>
      getYacStatesObservable();

      /// Get the observable of OS batches received by this peer.
      rxcpp::observable<
          std::shared_ptr<shared_model::interface::TransactionBatch>>
      getOsBatchesObservable();

      /// Get the observable of OG proposals received by this peer.
      rxcpp::observable<std::shared_ptr<shared_model::interface::Proposal>>
      getOgProposalsObservable();

      /// Get the observable of block requests received by this peer.
      rxcpp::observable<LoaderBlockRequest> getLoaderBlockRequestObservable();

      /// Get the observable of blocks requests received by this peer.
      rxcpp::observable<LoaderBlocksRequest> getLoaderBlocksRequestObservable();

      /// Get the observable of ODOS proposal requests received by this peer.
      rxcpp::observable<iroha::consensus::Round>
      getProposalRequestsObservable();

      /// Get the observable of ODOS batches received by this peer.
      rxcpp::observable<std::shared_ptr<BatchesCollection>>
      getBatchesObservable();

      /**
       * Send the real peer votes from this peer analogous to the provided ones.
       *
       * @param incoming_votes - the votes to take as the base.
       */
      void voteForTheSame(
          const std::shared_ptr<const YacMessage> &incoming_votes);

      /**
       * Make a signature of the provided hash.
       *
       * @param hash - the hash to sign
       */
      std::shared_ptr<shared_model::interface::Signature> makeSignature(
          const shared_model::crypto::Blob &hash) const;

      /// Make a vote from this peer for the provided YAC hash.
      iroha::consensus::yac::VoteMessage makeVote(
          iroha::consensus::yac::YacHash yac_hash);

      /// Send the main peer the given MST state.
      void sendMstState(const iroha::MstState &state);

      /// Send the main peer the given YAC state.
      void sendYacState(
          const std::vector<iroha::consensus::yac::VoteMessage> &state);

      void sendProposal(
          std::unique_ptr<shared_model::interface::Proposal> proposal);

      void sendBatch(
          const std::shared_ptr<shared_model::interface::TransactionBatch>
              &batch);

      bool sendBlockRequest(const LoaderBlockRequest &request);

      size_t sendBlocksRequest(const LoaderBlocksRequest &request);

      /// Send the real peer the provided batches for proposal.
      void proposeBatches(BatchesCollection batches);

      /// Send the real peer the provided transactions for proposal.
      void proposeTransactions(
          std::vector<std::shared_ptr<shared_model::interface::Transaction>>
              transactions);

      /**
       * Request the real peer's on demand ordering service a proposal for the
       * given round.
       *
       * @param round - the round of requested proposal.
       * @param timeout - time to wait for the reply.
       * @return The proposal if it was received
       */
      boost::optional<std::shared_ptr<const shared_model::interface::Proposal>>
      sendProposalRequest(iroha::consensus::Round round,
                          std::chrono::milliseconds timeout) const;

     private:
      using MstTransport = iroha::network::MstTransportGrpc;
      using YacTransport = iroha::consensus::yac::NetworkImpl;
      using OsTransport = iroha::ordering::OrderingServiceTransportGrpc;
      using OgTransport = iroha::ordering::OrderingGateTransportGrpc;
      using OdOsTransport = iroha::ordering::transport::OnDemandOsServerGrpc;
      using AsyncCall =
          iroha::network::AsyncGrpcClient<google::protobuf::Empty>;

      /// Ensure the initialize() method was called.
      void ensureInitialized();

      bool initialized_{false};

      logger::LoggerPtr log_;
      logger::LoggerManagerTreePtr log_manager_;
      logger::LoggerManagerTreePtr consensus_log_manager_;
      logger::LoggerManagerTreePtr mst_log_manager_;
      logger::LoggerManagerTreePtr ordering_log_manager_;

      std::shared_ptr<shared_model::interface::CommonObjectsFactory>
          common_objects_factory_;
      std::shared_ptr<TransportFactoryType> transaction_factory_;
      std::shared_ptr<shared_model::interface::TransactionBatchFactory>
          transaction_batch_factory_;
      std::shared_ptr<iroha::ordering::transport::OnDemandOsClientGrpc::
                          TransportFactoryType>
          proposal_factory_;
      std::shared_ptr<shared_model::interface::TransactionBatchParser>
          batch_parser_;

      const std::string listen_ip_;
      size_t internal_port_;
      std::unique_ptr<shared_model::crypto::Keypair> keypair_;

      std::shared_ptr<shared_model::interface::Peer>
          this_peer_;  ///< this fake instance
      std::shared_ptr<shared_model::interface::Peer>
          real_peer_;  ///< the real instance

      std::shared_ptr<AsyncCall> async_call_;

      std::shared_ptr<MstTransport> mst_transport_;
      std::shared_ptr<YacTransport> yac_transport_;
      std::shared_ptr<OdOsTransport> od_os_transport_;
      std::shared_ptr<LoaderGrpc> synchronizer_transport_;

      std::shared_ptr<MstNetworkNotifier> mst_network_notifier_;
      std::shared_ptr<YacNetworkNotifier> yac_network_notifier_;
      std::shared_ptr<OsNetworkNotifier> os_network_notifier_;
      std::shared_ptr<OgNetworkNotifier> og_network_notifier_;
      std::shared_ptr<OnDemandOsNetworkNotifier> od_os_network_notifier_;

      std::shared_ptr<iroha::consensus::yac::YacCryptoProvider> yac_crypto_;

      std::shared_ptr<Behaviour> behaviour_;
      std::shared_ptr<BlockStorage> block_storage_;
      ProposalStorage proposal_storage_;

      mutable std::shared_timed_mutex behaviour_mutex_;
    };

  }  // namespace fake_peer
}  // namespace integration_framework

#endif /* INTEGRATION_FRAMEWORK_FAKE_PEER_HPP_ */
