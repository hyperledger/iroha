/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_APPLICATION_HPP
#define IROHA_APPLICATION_HPP

#include <optional>

#include "consensus/consensus_block_cache.hpp"
#include "consensus/gate_object.hpp"
#include "cryptography/crypto_provider/abstract_crypto_model_signer.hpp"
#include "cryptography/keypair.hpp"
#include "http/http_server.hpp"
#include "interfaces/queries/blocks_query.hpp"
#include "interfaces/queries/query.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"
#include "main/impl/block_loader_init.hpp"
#include "main/iroha_conf_loader.hpp"
#include "main/iroha_status.hpp"
#include "main/server_runner.hpp"
#include "main/startup_params.hpp"
#include "main/subscription_fwd.hpp"
#include "torii/tls_params.hpp"

namespace google::protobuf {
  class Empty;
}

namespace evpp::evpphttp {
  class Service;
}

namespace iroha {
  class PendingTransactionStorage;
  class MstProcessor;
  class MstStorage;
  namespace ametsuchi {
    struct RocksDBPort;
    struct RocksDBContext;
    class WsvRestorer;
    class TxPresenceCache;
    class Storage;
    class ReconnectionStrategyFactory;
    class PostgresOptions;
    class RocksDbOptions;
    struct PoolWrapper;
    struct RocksDBContext;
    class VmCaller;
  }  // namespace ametsuchi
  namespace consensus {
    namespace yac {
      class YacInit;
    }  // namespace yac
  }    // namespace consensus
  namespace network {
    template <typename Response>
    class AsyncGrpcClient;
    class BlockLoader;
    class ChannelPool;
    class GenericClientFactory;
    class ConsensusGate;
    class OrderingGate;
    class PeerCommunicationService;
    class PeerTlsCertificatesProvider;
    struct GrpcChannelParams;
    struct TlsCredentials;
  }  // namespace network
  namespace ordering {
    class OnDemandOrderingInit;
  }
  namespace protocol {
    class Proposal;
    class Query;
    class BlocksQuery;
  }  // namespace protocol
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
    class TransactionProcessor;
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
    template <typename Interface, typename Transport>
    class AbstractTransportFactory;
    class Proposal;
    class QueryResponseFactory;
    class TransactionBatchFactory;
    class TransactionBatchParser;
    class TransactionBatch;
  }  // namespace interface
  namespace validation {
    struct Settings;
  }
}  // namespace shared_model

class Irohad {
 public:
  using RunResult = iroha::expected::Result<void, std::string>;

  /**
   * Constructor that initializes common iroha pipeline
   * @param pg_opt - connection options for PostgresSQL
   * @param listen_ip - ip address for opening ports (internal & torii)
   * not considered as expired (in minutes)
   * @param keypair - public and private keys for crypto signer
   * @param logger_manager - the logger manager to use
   * @param startup_wsv_data_policy - @see StartupWsvDataPolicy
   * @param maybe_grpc_channel_params - parameters for all grpc clients
   * (optional). Default gRPC configuration is used if not provided
   * @param opt_mst_gossip_params - parameters for Gossip MST propagation
   * (optional). If not provided, disables mst processing support
   * @see iroha::torii::TlsParams
   * @param inter_peer_tls_config - set up TLS in peer-to-peer communication
   * TODO mboldyrev 03.11.2018 IR-1844 Refactor the constructor.
   */
  Irohad(const IrohadConfig &config,
         std::unique_ptr<iroha::ametsuchi::PostgresOptions> pg_opt,
         std::unique_ptr<iroha::ametsuchi::RocksDbOptions> rdb_opt,
         const std::string &listen_ip,
         const boost::optional<shared_model::crypto::Keypair> &keypair,
         logger::LoggerManagerTreePtr logger_manager,
         iroha::StartupWsvDataPolicy startup_wsv_data_policy,
         iroha::StartupWsvSynchronizationPolicy startup_wsv_sync_policy,
         std::optional<std::shared_ptr<const iroha::network::GrpcChannelParams>>
             maybe_grpc_channel_params,
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
  virtual RunResult dropStorage();

  RunResult resetWsv();

  void printDbStatus();

  /**
   * Run worker threads for start performing
   * @return void value on success, error message otherwise
   */
  RunResult run();

  virtual ~Irohad();

 protected:
  // -----------------------| component initialization |------------------------
  virtual RunResult initStorage(
      iroha::StartupWsvDataPolicy startup_wsv_data_policy,
      iroha::StorageType type);

  RunResult initTlsCredentials();

  RunResult initPeerCertProvider();

  RunResult initClientFactory();

  virtual RunResult initCryptoProvider();

  virtual RunResult initBatchParser();

  virtual RunResult initValidators();

  virtual RunResult initNetworkClient();

  virtual RunResult initFactories();

  virtual RunResult initPersistentCache();

  virtual RunResult initPendingTxsStorageWithCache();

  virtual RunResult initOrderingGate();

  virtual RunResult initSimulator();

  virtual RunResult initConsensusCache();

  virtual RunResult initBlockLoader();

  virtual RunResult initConsensusGate();

  virtual RunResult initSynchronizer();

  virtual RunResult initPeerCommunicationService();

  virtual RunResult initStatusBus();

  virtual RunResult initPendingTxsStorage();

  virtual RunResult initTransactionCommandService();

  virtual RunResult initQueryService();

  virtual RunResult initSettings();

  virtual RunResult initNodeStatus();

  virtual RunResult initValidatorsConfigs();

  virtual RunResult initHttpServer();

  /**
   * Initialize WSV restorer
   */
  virtual RunResult initWsvRestorer();

  // constructor dependencies
  IrohadConfig const config_;
  const std::string listen_ip_;
  boost::optional<shared_model::crypto::Keypair> keypair_;
  iroha::StartupWsvSynchronizationPolicy startup_wsv_sync_policy_;
  std::optional<std::shared_ptr<const iroha::network::GrpcChannelParams>>
      maybe_grpc_channel_params_;
  boost::optional<IrohadConfig::InterPeerTls> inter_peer_tls_config_;

  boost::optional<std::shared_ptr<const iroha::network::TlsCredentials>>
      my_inter_peer_tls_creds_;
  boost::optional<std::shared_ptr<const iroha::network::TlsCredentials>>
      torii_tls_creds_;
  boost::optional<
      std::shared_ptr<const iroha::network::PeerTlsCertificatesProvider>>
      peer_tls_certificates_provider_;

  // pending transactions storage
  std::shared_ptr<iroha::PendingTransactionStorage> pending_txs_storage_;

  // query response factory
  std::shared_ptr<shared_model::interface::QueryResponseFactory>
      query_response_factory_;

  // ------------------------| internal dependencies |-------------------------
  std::optional<std::unique_ptr<iroha::ametsuchi::VmCaller>> vm_caller_;
  std::shared_ptr<iroha::ametsuchi::RocksDBContext> db_context_;

 public:
  std::unique_ptr<iroha::ametsuchi::PostgresOptions> pg_opt_;
  std::unique_ptr<iroha::ametsuchi::RocksDbOptions> rdb_opt_;
  std::shared_ptr<iroha::ametsuchi::Storage> storage;

 protected:
  std::shared_ptr<iroha::Subscription> subscription_engine_;

  // initialization objects
  std::shared_ptr<iroha::ordering::OnDemandOrderingInit> ordering_init;
  std::shared_ptr<iroha::consensus::yac::YacInit> yac_init;
  iroha::network::BlockLoaderInit loader_init;

  // IR-907 14.09.2020 @lebdron: remove it from here
  std::shared_ptr<iroha::ametsuchi::PoolWrapper> pool_wrapper_;

  std::shared_ptr<iroha::network::GenericClientFactory>
      inter_peer_client_factory_;

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

  // transaction service
  std::shared_ptr<iroha::torii::TransactionProcessor> tx_processor;
  std::shared_ptr<iroha::torii::CommandService> command_service;
  std::shared_ptr<iroha::torii::CommandServiceTransportGrpc>
      command_service_transport;

  // subscriptions
  using MstStateSubscriber = iroha::BaseSubscriber<
      bool,
      std::shared_ptr<shared_model::interface::TransactionBatch>>;
  std::shared_ptr<MstStateSubscriber> mst_state_update_;
  std::shared_ptr<MstStateSubscriber> mst_state_prepared_;
  std::shared_ptr<MstStateSubscriber> mst_state_expired_;

  std::shared_ptr<iroha::BaseSubscriber<
      iroha::utils::ReadWriteObject<iroha::IrohaStoredStatus, std::mutex>,
      iroha::IrohaStatus>>
      iroha_status_subscription_;

  // query service
  std::shared_ptr<iroha::torii::QueryService> query_service;

  // Http server
  std::unique_ptr<iroha::network::HttpServer> http_server_;

  // consensus gate
  std::shared_ptr<iroha::network::ConsensusGate> consensus_gate;

  std::unique_ptr<iroha::network::ServerRunner> torii_server;
  boost::optional<std::unique_ptr<iroha::network::ServerRunner>>
      torii_tls_server = boost::none;
  std::unique_ptr<iroha::network::ServerRunner> internal_server;

  logger::LoggerManagerTreePtr log_manager_;  ///< application root log manager

  logger::LoggerPtr log_;  ///< log for local messages
};

#endif  // IROHA_APPLICATION_HPP
