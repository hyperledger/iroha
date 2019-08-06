/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_INTEGRATION_FRAMEWORK_HPP
#define IROHA_INTEGRATION_FRAMEWORK_HPP

#include <algorithm>
#include <chrono>
#include <exception>
#include <functional>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include <boost/filesystem.hpp>
#include "backend/protobuf/queries/proto_query.hpp"
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "backend/protobuf/transaction_responses/proto_tx_response.hpp"
#include "framework/integration_framework/iroha_instance.hpp"
#include "framework/integration_framework/test_irohad.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "interfaces/iroha_internal/transaction_sequence.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager_fwd.hpp"
#include "multi_sig_transactions/state/mst_state.hpp"
#include "network/impl/async_grpc_client.hpp"
#include "network/mst_transport.hpp"
#include "ordering/impl/on_demand_os_client_grpc.hpp"
#include "torii/command_client.hpp"
#include "torii/query_client.hpp"

namespace shared_model {
  namespace crypto {
    class Keypair;
  }
  namespace interface {
    class CommonObjectsFactory;
    class Block;
    class Proposal;
  }  // namespace interface
  namespace proto {
    class Block;
  }
}  // namespace shared_model
namespace iroha {
  namespace consensus {
    namespace yac {
      class YacNetwork;
      struct VoteMessage;
    }  // namespace yac
    struct Round;
  }  // namespace consensus
  namespace network {
    class MstTransportGrpc;
    class OrderingServiceTransport;
  }  // namespace network
  namespace validation {
    struct VerifiedProposalAndErrors;
  }
}  // namespace iroha

namespace integration_framework {

  namespace fake_peer {
    class FakePeer;
  }

  class PortGuard;

  using std::chrono::milliseconds;

  /// Get the default logger of ITF.
  logger::LoggerManagerTreePtr getDefaultItfLogManager();

  class IntegrationTestFramework {
   private:
    using VerifiedProposalType =
        std::shared_ptr<iroha::validation::VerifiedProposalAndErrors>;
    using BlockType = std::shared_ptr<const shared_model::interface::Block>;
    using TxResponseType =
        std::shared_ptr<shared_model::interface::TransactionResponse>;

   public:
    using TransactionBatchType = shared_model::interface::TransactionBatch;
    using TransactionBatchSPtr = std::shared_ptr<TransactionBatchType>;

   private:
    std::mutex queue_mu;
    std::condition_variable queue_cond;

   public:
    /**
     * Construct test framework instance
     * @param maximum_proposal_size - Maximum number of transactions per
     * proposal
     * @param dbname - override database name to use (optional)
     * @param cleanup_on_exit - whether to clean resources on exit
     * @param mst_support - enables multisignature tx support
     * @param block_store_path - specifies path where blocks will be stored
     * @param proposal_waiting - timeout for next proposal appearing
     * @param block_waiting - timeout for next committed block appearing
     * @param log_manager - log manager
     *
     * TODO 21/12/2017 muratovv make relation of timeouts with instance's config
     */
    explicit IntegrationTestFramework(
        size_t maximum_proposal_size,
        const boost::optional<std::string> &dbname = boost::none,
        bool cleanup_on_exit = true,
        bool mst_support = false,
        const boost::optional<std::string> block_store_path = boost::none,
        milliseconds proposal_waiting = milliseconds(20000),
        milliseconds block_waiting = milliseconds(20000),
        milliseconds tx_response_waiting = milliseconds(10000),
        logger::LoggerManagerTreePtr log_manager = getDefaultItfLogManager());

    ~IntegrationTestFramework();

    /// Add a fake peer with given key.
    std::shared_ptr<fake_peer::FakePeer> addFakePeer(
        const boost::optional<shared_model::crypto::Keypair> &key);

    /// Add the given amount of fake peers with generated default keys and
    /// "honest" behaviours.
    std::vector<std::shared_ptr<fake_peer::FakePeer>> addFakePeers(
        size_t amount);

    /**
     * Construct default genesis block.
     *
     * Genesis block contains single transaction that
     * creates an admin account (kAdminName) with its role (kAdminRole), a
     * domain (kDomain) with its default role (kDefaultRole), and an asset
     * (kAssetName).
     * @param key - signing key
     * @return signed genesis block
     */
    shared_model::proto::Block defaultBlock(
        const shared_model::crypto::Keypair &key) const;

    /// Construct default genesis block using the my_key_ key.
    shared_model::proto::Block defaultBlock() const;

    /// Set the provided genesis block.
    IntegrationTestFramework &setGenesisBlock(
        const shared_model::interface::Block &block);

    /**
     * Initialize Iroha instance with default genesis block and provided signing
     * key
     * @param keypair - signing key
     * @return this
     */
    IntegrationTestFramework &setInitialState(
        const shared_model::crypto::Keypair &keypair);

    /// Set Gossip MST propagation parameters.
    IntegrationTestFramework &setMstGossipParams(
        std::chrono::milliseconds mst_gossip_emitting_period,
        uint32_t mst_gossip_amount_per_once);

    /**
     * Initialize Iroha instance with provided genesis block and signing key
     * @param keypair - signing key
     * @param block - genesis block used for iroha initialization
     * @return this
     */
    IntegrationTestFramework &setInitialState(
        const shared_model::crypto::Keypair &keypair,
        const shared_model::interface::Block &block);

    /**
     * Initialize Iroha instance using the data left in block store from
     * previous launch of Iroha
     * @param keypair - signing key used for initialization of previous instance
     */
    IntegrationTestFramework &recoverState(
        const shared_model::crypto::Keypair &keypair);

    /**
     * Send transaction to Iroha without wating for proposal and validating its
     * status
     * @param tx - transaction to send
     */
    IntegrationTestFramework &sendTxWithoutValidation(
        const shared_model::proto::Transaction &tx);

    /**
     * Send transaction to Iroha and validate its status
     * @param tx - transaction for sending
     * @param validation - callback for transaction status validation that
     * receives object of type \relates shared_model::proto::TransactionResponse
     * by reference
     * @return this
     */
    IntegrationTestFramework &sendTx(
        const shared_model::proto::Transaction &tx,
        std::function<void(const shared_model::proto::TransactionResponse &)>
            validation);

    /**
     * Send transaction to Iroha without status validation
     * @param tx - transaction for sending
     * @return this
     */
    IntegrationTestFramework &sendTx(
        const shared_model::proto::Transaction &tx);

    /**
     * Send transaction to Iroha with awaiting proposal
     * and without status validation
     * @param tx - transaction for sending
     * @return this
     */
    IntegrationTestFramework &sendTxAwait(
        const shared_model::proto::Transaction &tx);

    /**
     * Send transaction to Iroha with awaiting proposal and without status
     * validation. Issue callback on the result.
     * @param tx - transaction for sending
     * @param check - callback for checking committed block
     * @return this
     */
    IntegrationTestFramework &sendTxAwait(
        const shared_model::proto::Transaction &tx,
        std::function<void(const BlockType &)> check);

    /**
     * Send transactions to Iroha and validate obtained statuses
     * @param tx_sequence - transactions sequence
     * @param validation - callback for transactions statuses validation.
     * Applied to the vector of returned statuses
     * @return this
     */
    IntegrationTestFramework &sendTxSequence(
        const shared_model::interface::TransactionSequence &tx_sequence,
        std::function<void(std::vector<shared_model::proto::TransactionResponse>
                               &)> validation = [](const auto &) {});

    /**
     * Send transactions to Iroha with awaiting proposal and without status
     * validation
     * @param tx_sequence - sequence for sending
     * @param check - callback for checking committed block
     * @return this
     */
    IntegrationTestFramework &sendTxSequenceAwait(
        const shared_model::interface::TransactionSequence &tx_sequence,
        std::function<void(const BlockType &)> check);

    /**
     * Check current status of transaction
     * @param hash - hash of transaction to check
     * @param validation - callback that receives transaction response
     * @return this
     */
    IntegrationTestFramework &getTxStatus(
        const shared_model::crypto::Hash &hash,
        std::function<void(const shared_model::proto::TransactionResponse &)>
            validation);

    /**
     * Send query to Iroha and validate the response
     * @param qry - query to be requested
     * @param validation - callback for query result check that receives object
     * of type \relates shared_model::proto::QueryResponse by reference
     * @return this
     */
    IntegrationTestFramework &sendQuery(
        const shared_model::proto::Query &qry,
        std::function<void(const shared_model::proto::QueryResponse &)>
            validation);

    /**
     * Send query to Iroha without response validation
     * @param qry - query to be requested
     * @return this
     */
    IntegrationTestFramework &sendQuery(const shared_model::proto::Query &qry);

    /// Send proposal to this peer's ordering service.
    IntegrationTestFramework &sendProposal(
        std::unique_ptr<shared_model::interface::Proposal> proposal);

    /// Send a batch of transactions to this peer's ordering service.
    IntegrationTestFramework &sendBatch(const TransactionBatchSPtr &batch);

    /**
     * Send batches of transactions to this peer's on-demand ordering service.
     * @param batches - the batch to send
     * @return this
     */
    IntegrationTestFramework &sendBatches(
        const std::vector<TransactionBatchSPtr> &batches);

    /**
     * Request a proposal from this peer's on-demand ordering service.
     * @param round - the round for which to request a proposal
     * @param timeout - the timeout for waiting the proposal
     * @return the proposal if received one
     */
    boost::optional<std::shared_ptr<const shared_model::interface::Proposal>>
    requestProposal(const iroha::consensus::Round &round,
                    std::chrono::milliseconds timeout);

    /**
     * Send MST state message to this peer.
     * @param src_key - the key of the peer which the message appears to come
     * from
     * @param mst_state - the MST state to send
     * @return this
     */
    IntegrationTestFramework &sendMstState(
        const shared_model::crypto::PublicKey &src_key,
        const iroha::MstState &mst_state);

    /**
     * Send MST state message to this peer.
     * @param src_key - the key of the peer which the message appears to come
     * from
     * @param mst_state - the MST state to send
     * @return this
     */
    IntegrationTestFramework &sendYacState(
        const std::vector<iroha::consensus::yac::VoteMessage> &yac_state);

    /**
     * Request next proposal from queue and serve it with custom handler
     * @param validation - callback that receives object of type \relates
     * std::shared_ptr<shared_model::interface::Proposal> by reference
     * @return this
     */
    IntegrationTestFramework &checkProposal(
        std::function<void(
            const std::shared_ptr<const shared_model::interface::Proposal> &)>
            validation);

    /**
     * Request next proposal from queue and skip it
     * @return this
     */
    IntegrationTestFramework &skipProposal();

    /**
     * Request next verified proposal from queue and check it with provided
     * function
     * @param validation - callback that receives object of type \relates
     * std::shared_ptr<shared_model::interface::Proposal> by reference
     * @return this
     * TODO mboldyrev 27.10.2018: make validation function accept
     *                IR-1822     VerifiedProposalType argument
     */
    IntegrationTestFramework &checkVerifiedProposal(
        std::function<void(
            const std::shared_ptr<const shared_model::interface::Proposal> &)>
            validation);

    /**
     * Request next verified proposal from queue and skip it
     * @return this
     */
    IntegrationTestFramework &skipVerifiedProposal();

    /**
     * Request next block from queue and serve it with custom handler
     * @param validation - callback that receives object of type \relates
     * std::shared_ptr<const shared_model::interface::Block> by reference
     * @return this
     */
    IntegrationTestFramework &checkBlock(
        std::function<void(const BlockType &)> validation);

    /**
     * Request next block from queue and skip it
     * @return this
     */
    IntegrationTestFramework &skipBlock();

    rxcpp::observable<std::shared_ptr<iroha::MstState>>
    getMstStateUpdateObservable();

    rxcpp::observable<iroha::BatchPtr> getMstPreparedBatchesObservable();

    rxcpp::observable<iroha::BatchPtr> getMstExpiredBatchesObservable();

    rxcpp::observable<iroha::consensus::GateObject> getYacOnCommitObservable();

    rxcpp::observable<iroha::synchronizer::SynchronizationEvent>
    getPcsOnCommitObservable();

    /// Get block query for iroha block storage.
    std::shared_ptr<iroha::ametsuchi::BlockQuery> getBlockQuery();

    /**
     * Request next status of the transaction
     * @param tx_hash is hash for filtering responses
     * @return this
     */
    IntegrationTestFramework &checkStatus(
        const shared_model::interface::types::HashType &tx_hash,
        std::function<void(const shared_model::proto::TransactionResponse &)>
            validation);

    /**
     * Reports the port used for internal purposes like MST communications
     * @return occupied port number
     */
    size_t internalPort() const;

    /**
     * Shutdown ITF instance
     */
    void done();

    /// Get the controlled Iroha instance.
    IrohaInstance &getIrohaInstance();

    /// Set the ITF peer keypair and initialize irohad pipeline.
    void initPipeline(const shared_model::crypto::Keypair &keypair);

    /// Start the ITF.
    void subscribeQueuesAndRun();

    /// Get interface::Peer object for this instance.
    std::shared_ptr<shared_model::interface::Peer> getThisPeer() const;

    /// Get this node address.
    std::string getAddress() const;

   protected:
    using AsyncCall = iroha::network::AsyncGrpcClient<google::protobuf::Empty>;

    /**
     * A wrapper over a queue that provides thread safety and blocking pop
     * operation with timeout. Is intended to be used as an intermediate storage
     * for intercepted objects from iroha instance on their way to checker
     * predicates.
     */
    template <typename T>
    class CheckerQueue;

    /**
     * general way to fetch object from concurrent queue
     * @tparam Queue - Type of queue
     * @tparam ObjectType - Type of fetched object
     * @tparam WaitTime - time for waiting if data doesn't appear
     * @param queue - queue instance for fetching
     * @param ref_for_insertion - reference to insert object
     * @param wait - time of waiting
     * @param error_reason - reason if there is no appeared object at all
     */
    template <typename Queue, typename ObjectType, typename WaitTime>
    void fetchFromQueue(Queue &queue,
                        ObjectType &ref_for_insertion,
                        const WaitTime &wait,
                        const std::string &error_reason);

    /// Cleanup the resources
    void cleanup();

    logger::LoggerPtr log_;
    logger::LoggerManagerTreePtr log_manager_;

    std::unique_ptr<
        CheckerQueue<std::shared_ptr<const shared_model::interface::Proposal>>>
        proposal_queue_;
    std::unique_ptr<CheckerQueue<VerifiedProposalType>>
        verified_proposal_queue_;
    std::unique_ptr<CheckerQueue<BlockType>> block_queue_;
    std::map<std::string, std::unique_ptr<CheckerQueue<TxResponseType>>>
        responses_queues_;

    std::unique_ptr<PortGuard> port_guard_;
    size_t torii_port_;
    size_t internal_port_;
    std::shared_ptr<IrohaInstance> iroha_instance_;
    torii::CommandSyncClient command_client_;
    torii_utils::QuerySyncClient query_client_;

    std::shared_ptr<AsyncCall> async_call_;

    // config area

    /// maximum time of waiting before appearing next transaction response
    milliseconds tx_response_waiting;

    size_t maximum_proposal_size_;

    std::shared_ptr<shared_model::interface::CommonObjectsFactory>
        common_objects_factory_;
    std::shared_ptr<shared_model::interface::AbstractTransportFactory<
        shared_model::interface::Transaction,
        iroha::protocol::Transaction>>
        transaction_factory_;
    std::shared_ptr<shared_model::interface::TransactionBatchParser>
        batch_parser_;
    std::shared_ptr<shared_model::validation::AbstractValidator<
        shared_model::interface::TransactionBatch>>
        batch_validator_;
    std::shared_ptr<shared_model::interface::TransactionBatchFactory>
        transaction_batch_factory_;
    std::shared_ptr<
        iroha::ordering::transport::OnDemandOsClientGrpc::TransportFactoryType>
        proposal_factory_;
    std::shared_ptr<iroha::ametsuchi::TxPresenceCache> tx_presence_cache_;
    std::shared_ptr<iroha::network::MstTransportGrpc> mst_transport_;
    std::shared_ptr<iroha::consensus::yac::YacNetwork> yac_transport_;

    boost::optional<shared_model::crypto::Keypair> my_key_;
    std::shared_ptr<shared_model::interface::Peer> this_peer_;

   private:
    bool cleanup_on_exit_;
    std::vector<std::shared_ptr<fake_peer::FakePeer>> fake_peers_;
    std::vector<std::unique_ptr<ServerRunner>> fake_peers_servers_;
  };

}  // namespace integration_framework

#endif  // IROHA_INTEGRATION_FRAMEWORK_HPP
