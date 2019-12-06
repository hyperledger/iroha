/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_APPLICATION_HPP
#define IROHA_APPLICATION_HPP

#include "consensus/consensus_block_cache.hpp"
#include "consensus/gate_object.hpp"
#include "cryptography/crypto_provider/abstract_crypto_model_signer.hpp"
#include "cryptography/keypair.hpp"
#include "interfaces/queries/blocks_query.hpp"
#include "interfaces/queries/query.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"
#include "main/impl/block_loader_init.hpp"
#include "main/impl/on_demand_ordering_init.hpp"
#include "main/iroha_conf_loader.hpp"
#include "main/server_runner.hpp"
#include "multi_sig_transactions/gossip_propagation_strategy_params.hpp"
#include "torii/tls_params.hpp"

namespace iroha {
  class PendingTransactionStorage;
  class PendingTransactionStorageInit;
  class MstProcessor;
  namespace ametsuchi {
    class WsvRestorer;
    class TxPresenceCache;
    class Storage;
    class ReconnectionStrategyFactory;
    class PostgresOptions;
    struct PoolWrapper;
  }  // namespace ametsuchi
  namespace consensus {
    namespace yac {
      class YacInit;
    }  // namespace yac
  }    // namespace consensus
  namespace network {
    class BlockLoader;
    class ConsensusGate;
    class MstTransport;
    class OrderingGate;
    class PeerCommunicationService;
    class PeerTlsCertificatesProvider;
    struct TlsCredentials;
  }  // namespace network
  namespace simulator {
    class Simulator;
  }
  namespace synchronizer {
    class Synchronizer;
  }
  namespace torii {
    class QueryProcessor;
    class StatusBus;
    class CommandService;
    class CommandServiceTransportGrpc;
    class QueryService;

    struct TlsParams;
  }  // namespace torii
  namespace validation {
    class ChainValidator;
    class StatefulValidator;
  }  // namespace validation
}  // namespace iroha

namespace shared_model {
  namespace crypto {
    class Keypair;
  }
  namespace interface {
    class QueryResponseFactory;
    class TransactionBatchFactory;
  }  // namespace interface
}  // namespace shared_model

class Irohad {
 public:
  using RunResult = iroha::expected::Result<void, std::string>;

  /**
   * Constructor that initializes common iroha pipeline
   * @param block_store_dir - folder where blocks will be stored
   * @param pg_opt - connection options for PostgresSQL
   * @param listen_ip - ip address for opening ports (internal & torii)
   * @param torii_port - port for torii binding
   * @param internal_port - port for internal communication - ordering service,
   * consensus, and block loader
   * @param max_proposal_size - maximum transactions that possible appears in
   * one proposal
   * @param proposal_delay - maximum waiting time util emitting new proposal
   * @param vote_delay - waiting time before sending vote to next peer
   * @param mst_expiration_time - maximum time until until MST transaction is
   * not considered as expired (in minutes)
   * @param keypair - public and private keys for crypto signer
   * @param max_rounds_delay - maximum delay between consecutive rounds without
   * transactions
   * @param stale_stream_max_rounds - maximum number of rounds between
   * consecutive status emissions
   * @param opt_alternative_peers - optional alternative initial peers list
   * @param logger_manager - the logger manager to use
   * @param opt_mst_gossip_params - parameters for Gossip MST propagation
   * (optional). If not provided, disables mst processing support
   * TODO mboldyrev 03.11.2018 IR-1844 Refactor the constructor.
   * @param torii_tls_params - optional TLS params for torii.
   * @see iroha::torii::TlsParams
   * @param inter_peer_tls_config - set up TLS in peer-to-peer communication
   */
  Irohad(const boost::optional<std::string> &block_store_dir,
         std::unique_ptr<iroha::ametsuchi::PostgresOptions> pg_opt,
         const std::string &listen_ip,
         size_t torii_port,
         size_t internal_port,
         size_t max_proposal_size,
         std::chrono::milliseconds proposal_delay,
         std::chrono::milliseconds vote_delay,
         std::chrono::minutes mst_expiration_time,
         const shared_model::crypto::Keypair &keypair,
         std::chrono::milliseconds max_rounds_delay,
         size_t stale_stream_max_rounds,
         boost::optional<shared_model::interface::types::PeerList>
             opt_alternative_peers,
         logger::LoggerManagerTreePtr logger_manager,
         const boost::optional<iroha::GossipPropagationStrategyParams>
             &opt_mst_gossip_params = boost::none,
         const boost::optional<iroha::torii::TlsParams> &torii_tls_params =
             boost::none,
         boost::optional<IrohadConfig::InterPeerTls> inter_peer_tls_config =
             boost::none);

  /**
   * Initialization of whole objects in system
   */
  virtual RunResult init();

  /**
   * Restore World State View
   * @return void value on success, error message otherwise
   */
  RunResult restoreWsv();

  /**
   * Check that the provided keypair is present in the ledger
   */
  RunResult validateKeypair();

  /**
   * Drop wsv and block store
   */
  virtual void dropStorage();

  /**
   * Run worker threads for start performing
   * @return void value on success, error message otherwise
   */
  RunResult run();

  virtual ~Irohad();

 protected:
  // -----------------------| component initialization |------------------------
  virtual RunResult initStorage(
      std::unique_ptr<iroha::ametsuchi::PostgresOptions> pg_opt);

  RunResult initTlsCredentials();

  RunResult initPeerCertProvider();

  virtual RunResult initCryptoProvider();

  virtual RunResult initBatchParser();

  virtual RunResult initValidators();

  virtual RunResult initNetworkClient();

  virtual RunResult initFactories();

  virtual RunResult initPersistentCache();

  virtual RunResult initOrderingGate();

  virtual RunResult initSimulator();

  virtual RunResult initConsensusCache();

  virtual RunResult initBlockLoader();

  virtual RunResult initConsensusGate();

  virtual RunResult initSynchronizer();

  virtual RunResult initPeerCommunicationService();

  virtual RunResult initStatusBus();

  virtual RunResult initMstProcessor();

  virtual RunResult initPendingTxsStorage();

  virtual RunResult initTransactionCommandService();

  virtual RunResult initQueryService();

  virtual RunResult initSettings();

  virtual RunResult initValidatorsConfigs();

  /**
   * Initialize WSV restorer
   */
  virtual RunResult initWsvRestorer();

  // constructor dependencies
  const boost::optional<std::string> block_store_dir_;
  const std::string listen_ip_;
  size_t torii_port_;
  boost::optional<iroha::torii::TlsParams> torii_tls_params_;
  size_t internal_port_;
  size_t max_proposal_size_;
  std::chrono::milliseconds proposal_delay_;
  std::chrono::milliseconds vote_delay_;
  bool is_mst_supported_;
  std::chrono::minutes mst_expiration_time_;
  std::chrono::milliseconds max_rounds_delay_;
  size_t stale_stream_max_rounds_;
  const boost::optional<shared_model::interface::types::PeerList>
      opt_alternative_peers_;
  boost::optional<iroha::GossipPropagationStrategyParams>
      opt_mst_gossip_params_;
  boost::optional<IrohadConfig::InterPeerTls> inter_peer_tls_config_;

  boost::optional<std::shared_ptr<const iroha::network::TlsCredentials>>
      my_inter_peer_tls_creds_;
  boost::optional<std::shared_ptr<const iroha::network::TlsCredentials>>
      torii_tls_creds_;
  boost::optional<
      std::shared_ptr<const iroha::network::PeerTlsCertificatesProvider>>
      peer_tls_certificates_provider_;

  std::unique_ptr<iroha::PendingTransactionStorageInit>
      pending_txs_storage_init;

  // pending transactions storage
  std::shared_ptr<iroha::PendingTransactionStorage> pending_txs_storage_;

  // query response factory
  std::shared_ptr<shared_model::interface::QueryResponseFactory>
      query_response_factory_;

  // ------------------------| internal dependencies |-------------------------
 public:
  shared_model::crypto::Keypair keypair;
  std::shared_ptr<iroha::ametsuchi::Storage> storage;

 protected:
  // initialization objects
  iroha::network::OnDemandOrderingInit ordering_init;
  std::unique_ptr<iroha::consensus::yac::YacInit> yac_init;
  iroha::network::BlockLoaderInit loader_init;

  std::shared_ptr<iroha::ametsuchi::PoolWrapper> pool_wrapper_;

  // Settings
  std::shared_ptr<const shared_model::validation::Settings> settings_;

  // WSV restorer
  std::shared_ptr<iroha::ametsuchi::WsvRestorer> wsv_restorer_;

  // crypto provider
  std::shared_ptr<shared_model::crypto::AbstractCryptoModelSigner<
      shared_model::interface::Block>>
      crypto_signer_;

  // batch parser
  std::shared_ptr<shared_model::interface::TransactionBatchParser> batch_parser;

  // validators
  std::shared_ptr<shared_model::validation::ValidatorsConfig>
      validators_config_;
  std::shared_ptr<shared_model::validation::ValidatorsConfig>
      proposal_validators_config_;
  std::shared_ptr<shared_model::validation::ValidatorsConfig>
      block_validators_config_;
  std::shared_ptr<iroha::validation::StatefulValidator> stateful_validator;
  std::shared_ptr<iroha::validation::ChainValidator> chain_validator;

  // async call
  std::shared_ptr<iroha::network::AsyncGrpcClient<google::protobuf::Empty>>
      async_call_;

  // transaction batch factory
  std::shared_ptr<shared_model::interface::TransactionBatchFactory>
      transaction_batch_factory_;

  // transaction factory
  std::shared_ptr<shared_model::interface::AbstractTransportFactory<
      shared_model::interface::Transaction,
      iroha::protocol::Transaction>>
      transaction_factory;

  // query factory
  std::shared_ptr<shared_model::interface::AbstractTransportFactory<
      shared_model::interface::Query,
      iroha::protocol::Query>>
      query_factory;

  // blocks query factory
  std::shared_ptr<shared_model::interface::AbstractTransportFactory<
      shared_model::interface::BlocksQuery,
      iroha::protocol::BlocksQuery>>
      blocks_query_factory;

  // persistent cache
  std::shared_ptr<iroha::ametsuchi::TxPresenceCache> persistent_cache;

  // proposal factory
  std::shared_ptr<shared_model::interface::AbstractTransportFactory<
      shared_model::interface::Proposal,
      iroha::protocol::Proposal>>
      proposal_factory;

  // ordering gate
  std::shared_ptr<iroha::network::OrderingGate> ordering_gate;

  // simulator
  std::shared_ptr<iroha::simulator::Simulator> simulator;

  // block cache for consensus and block loader
  std::shared_ptr<iroha::consensus::ConsensusResultCache>
      consensus_result_cache_;

  // block loader
  std::shared_ptr<iroha::network::BlockLoader> block_loader;

  // synchronizer
  std::shared_ptr<iroha::synchronizer::Synchronizer> synchronizer;

  // pcs
  std::shared_ptr<iroha::network::PeerCommunicationService> pcs;

  // status bus
  std::shared_ptr<iroha::torii::StatusBus> status_bus_;

  // mst
  std::shared_ptr<iroha::network::MstTransport> mst_transport;
  std::shared_ptr<iroha::MstProcessor> mst_processor;

  // transaction service
  std::shared_ptr<iroha::torii::CommandService> command_service;
  std::shared_ptr<iroha::torii::CommandServiceTransportGrpc>
      command_service_transport;

  // query service
  std::shared_ptr<iroha::torii::QueryService> query_service;

  // consensus gate
  std::shared_ptr<iroha::network::ConsensusGate> consensus_gate;
  rxcpp::composite_subscription consensus_gate_objects_lifetime;
  rxcpp::subjects::subject<iroha::consensus::GateObject> consensus_gate_objects;
  rxcpp::composite_subscription consensus_gate_events_subscription;

  std::unique_ptr<iroha::network::ServerRunner> torii_server;
  boost::optional<std::unique_ptr<iroha::network::ServerRunner>>
      torii_tls_server = boost::none;
  std::unique_ptr<iroha::network::ServerRunner> internal_server;

  logger::LoggerManagerTreePtr log_manager_;  ///< application root log manager

  logger::LoggerPtr log_;  ///< log for local messages
};

#endif  // IROHA_APPLICATION_HPP
