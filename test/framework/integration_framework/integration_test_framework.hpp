/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_INTEGRATION_FRAMEWORK_HPP
#define IROHA_INTEGRATION_FRAMEWORK_HPP

#include <boost/filesystem.hpp>
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <rxcpp/rx-observable-fwd.hpp>

#include "consensus/gate_object.hpp"
#include "cryptography/keypair.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"
#include "main/iroha_conf_loader.hpp"
#include "main/startup_params.hpp"
#include "main/subscription_fwd.hpp"
#include "synchronizer/synchronizer_common.hpp"

namespace google::protobuf {
  class Empty;
}  // namespace google::protobuf

namespace shared_model {
  namespace crypto {
    class Keypair;
  }
  namespace interface {
    template <typename Interface, typename Transport>
    class AbstractTransportFactory;
    class CommonObjectsFactory;
    class Block;
    class Proposal;
    class TransactionBatch;
    class TransactionBatchFactory;
    class TransactionBatchParser;
    class TransactionResponse;
    class TransactionSequence;
  }  // namespace interface
  namespace proto {
    class Block;
    class Transaction;
    class TransactionResponse;
    class Query;
    class QueryResponse;
  }  // namespace proto
  namespace validation {
    template <typename Model>
    class AbstractValidator;
  }
}  // namespace shared_model
namespace iroha {
  namespace ametsuchi {
    class BlockQuery;
    class TxPresenceCache;
  }  // namespace ametsuchi
  namespace consensus {
    namespace yac {
      class YacNetwork;
      struct VoteMessage;
    }  // namespace yac
    struct Round;
  }  // namespace consensus
  namespace network {
    class GenericClientFactory;
    struct OrderingEvent;
    class ServerRunner;
    template <typename Response>
    class AsyncGrpcClient;
  }  // namespace network
  namespace protocol {
    class Proposal;
    class Transaction;
  }  // namespace protocol
  namespace simulator {
    struct VerifiedProposalCreatorEvent;
  }
  namespace validation {
    struct VerifiedProposalAndErrors;
  }
  class MstState;
}  // namespace iroha
namespace torii {
  class CommandSyncClient;
}
namespace torii_utils {
  class QuerySyncClient;
}

namespace integration_framework {

  namespace fake_peer {
    class FakePeer;
  }

  class PortGuard;
  class IrohaInstance;

  using std::chrono::milliseconds;

  /// Get the default logger of ITF.
  logger::LoggerManagerTreePtr getDefaultItfLogManager();

  class IntegrationTestFramework {
   private:
    using VerifiedProposalType =
        std::shared_ptr<iroha::validation::VerifiedProposalAndErrors>;
    using BlockType = std::shared_ptr<const shared_model::interface::Block>;

   public:
    using TransactionBatchType = shared_model::interface::TransactionBatch;
    using TransactionBatchSPtr = std::shared_ptr<TransactionBatchType>;

   public:
    /**
     * Construct test framework instance
     * @param maximum_proposal_size - Maximum number of transactions per
     * proposal
     * @param dbname - override database name to use (optional)
     * @param startup_wsv_data_policy - @see StartupWsvDataPolicy
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
        iroha::StorageType db_type,
        const boost::optional<std::string> &dbname = boost::none,
        iroha::StartupWsvDataPolicy startup_wsv_data_policy =
            iroha::StartupWsvDataPolicy::kDrop,
        bool cleanup_on_exit = true,
        bool mst_support = false,
        const boost::optional<std::string> block_store_path = boost::none,
        milliseconds proposal_waiting = milliseconds(20000),
        milliseconds block_waiting = milliseconds(20000),
        milliseconds tx_response_waiting_ms = milliseconds(10000),
        logger::LoggerManagerTreePtr log_manager = getDefaultItfLogManager(),
        std::string db_wsv_path = (boost::filesystem::temp_directory_path()
                                   / boost::filesystem::unique_path())
                                      .string(),
        std::string db_store_path = (boost::filesystem::temp_directory_path()
                                     / boost::filesystem::unique_path())
                                        .string());

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

    void printDbStatus();

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

    void unbind_guarded_port(uint16_t port);

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

    std::shared_ptr<iroha::Subscription> subscription;

    logger::LoggerPtr log_;
    logger::LoggerManagerTreePtr log_manager_;

    std::shared_ptr<
        CheckerQueue<std::shared_ptr<const shared_model::interface::Proposal>>>
        proposal_queue_;
    std::shared_ptr<iroha::BaseSubscriber<bool, iroha::network::OrderingEvent>>
        proposal_subscription_;
    std::shared_ptr<CheckerQueue<VerifiedProposalType>>
        verified_proposal_queue_;
    std::shared_ptr<
        iroha::BaseSubscriber<bool,
                              iroha::simulator::VerifiedProposalCreatorEvent>>
        verified_proposal_subscription_;
    std::shared_ptr<iroha::BaseSubscriber<
        bool,
        std::shared_ptr<shared_model::interface::Block const>>>
        block_subscription_;
    std::shared_ptr<CheckerQueue<BlockType>> block_queue_;

    struct ResponsesQueues;
    std::shared_ptr<ResponsesQueues> responses_queues_;
    std::shared_ptr<iroha::BaseSubscriber<
        bool,
        std::shared_ptr<shared_model::interface::TransactionResponse>>>
        responses_subscription_;
    std::chrono::milliseconds tx_response_waiting_ms_;

    std::unique_ptr<PortGuard> port_guard_;
    size_t torii_port_;
    IrohadConfig config_;
    std::shared_ptr<IrohaInstance> iroha_instance_;
    std::unique_ptr<torii::CommandSyncClient> command_client_;
    std::unique_ptr<torii_utils::QuerySyncClient> query_client_;

    std::shared_ptr<AsyncCall> async_call_;

    // config area

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
    std::shared_ptr<shared_model::interface::AbstractTransportFactory<
        shared_model::interface::Proposal,
        iroha::protocol::Proposal>>
        proposal_factory_;
    std::shared_ptr<iroha::ametsuchi::TxPresenceCache> tx_presence_cache_;

    std::shared_ptr<iroha::network::GenericClientFactory> client_factory_;
    std::shared_ptr<iroha::consensus::yac::YacNetwork> yac_transport_;

    std::optional<shared_model::crypto::Keypair> my_key_;
    std::shared_ptr<shared_model::interface::Peer> this_peer_;

   private:
    bool cleanup_on_exit_;
    std::vector<std::shared_ptr<fake_peer::FakePeer>> fake_peers_;
    std::vector<std::unique_ptr<iroha::network::ServerRunner>>
        fake_peers_servers_;
    std::string db_wsv_path_;
    std::string db_store_path_;
  };

}  // namespace integration_framework

#endif  // IROHA_INTEGRATION_FRAMEWORK_HPP
