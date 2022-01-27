/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/application.hpp"

#include <boost/filesystem.hpp>
#include <optional>

#include "ametsuchi/impl/pool_wrapper.hpp"
#include "ametsuchi/impl/rocksdb_storage_impl.hpp"
#include "ametsuchi/impl/storage_impl.hpp"
#include "ametsuchi/impl/tx_presence_cache_impl.hpp"
#include "ametsuchi/impl/wsv_restorer_impl.hpp"
#include "ametsuchi/vm_caller.hpp"
#include "backend/protobuf/proto_block_json_converter.hpp"
#include "backend/protobuf/proto_permission_to_string.hpp"
#include "backend/protobuf/proto_proposal_factory.hpp"
#include "backend/protobuf/proto_query_response_factory.hpp"
#include "backend/protobuf/proto_transport_factory.hpp"
#include "backend/protobuf/proto_tx_status_factory.hpp"
#include "common/bind.hpp"
#include "common/files.hpp"
#include "common/result_try.hpp"
#include "consensus/yac/consensus_outcome_type.hpp"
#include "consensus/yac/consistency_model.hpp"
#include "consensus/yac/supermajority_checker.hpp"
#include "cryptography/crypto_provider/crypto_model_signer.hpp"
#include "cryptography/default_hash_provider.hpp"
#include "generator/generator.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser_impl.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/impl/consensus_init.hpp"
#include "main/impl/on_demand_ordering_init.hpp"
#include "main/impl/pg_connection_init.hpp"
#include "main/impl/rocksdb_connection_init.hpp"
#include "main/impl/storage_init.hpp"
#include "main/server_runner.hpp"
#include "main/subscription.hpp"
#include "multi_sig_transactions/gossip_propagation_strategy.hpp"
#include "multi_sig_transactions/mst_processor_impl.hpp"
#include "multi_sig_transactions/mst_propagation_strategy_stub.hpp"
#include "multi_sig_transactions/mst_time_provider_impl.hpp"
#include "multi_sig_transactions/storage/mst_storage_impl.hpp"
#include "multi_sig_transactions/transport/mst_transport_grpc.hpp"
#include "multi_sig_transactions/transport/mst_transport_stub.hpp"
#include "network/impl/block_loader_impl.hpp"
#include "network/impl/channel_factory.hpp"
#include "network/impl/channel_pool.hpp"
#include "network/impl/client_factory_impl.hpp"
#include "network/impl/generic_client_factory.hpp"
#include "network/impl/peer_communication_service_impl.hpp"
#include "network/impl/peer_tls_certificates_provider_root.hpp"
#include "network/impl/peer_tls_certificates_provider_wsv.hpp"
#include "network/impl/tls_credentials.hpp"
#include "ordering/impl/on_demand_common.hpp"
#include "ordering/impl/on_demand_ordering_gate.hpp"
#include "pending_txs_storage/impl/pending_txs_storage_impl.hpp"
#include "simulator/impl/simulator.hpp"
#include "synchronizer/impl/synchronizer_impl.hpp"
#include "torii/impl/command_service_impl.hpp"
#include "torii/impl/command_service_transport_grpc.hpp"
#include "torii/processor/query_processor_impl.hpp"
#include "torii/processor/transaction_processor_impl.hpp"
#include "torii/query_service.hpp"
#include "torii/tls_params.hpp"
#include "validation/impl/chain_validator_impl.hpp"
#include "validation/impl/stateful_validator_impl.hpp"
#include "validators/always_valid_validator.hpp"
#include "validators/default_validator.hpp"
#include "validators/field_validator.hpp"
#include "validators/protobuf/proto_block_validator.hpp"
#include "validators/protobuf/proto_proposal_validator.hpp"
#include "validators/protobuf/proto_query_validator.hpp"
#include "validators/protobuf/proto_transaction_validator.hpp"

#if defined(USE_BURROW)
#include "ametsuchi/impl/burrow_vm_caller.hpp"
#endif

using namespace iroha;
using namespace iroha::ametsuchi;
using namespace iroha::simulator;
using namespace iroha::validation;
using namespace iroha::network;
using namespace iroha::synchronizer;
using namespace iroha::torii;
using namespace iroha::consensus::yac;

using shared_model::interface::types::PublicKeyHexStringView;

/// Consensus consistency model type.
static constexpr iroha::consensus::yac::ConsistencyModel
    kConsensusConsistencyModel = iroha::consensus::yac::ConsistencyModel::kCft;

static constexpr uint32_t kStaleStreamMaxRoundsDefault = 2;
static constexpr uint32_t kMstExpirationTimeDefault = 1440;
static constexpr uint32_t kMaxRoundsDelayDefault = 3000;

/**
 * Configuring iroha daemon
 */
Irohad::Irohad(
    const IrohadConfig &config,
    std::unique_ptr<ametsuchi::PostgresOptions> pg_opt,
    std::unique_ptr<iroha::ametsuchi::RocksDbOptions> rdb_opt,
    const std::string &listen_ip,
    const boost::optional<shared_model::crypto::Keypair> &keypair,
    logger::LoggerManagerTreePtr logger_manager,
    StartupWsvDataPolicy startup_wsv_data_policy,
    StartupWsvSynchronizationPolicy startup_wsv_sync_policy,
    std::optional<std::shared_ptr<const GrpcChannelParams>>
        maybe_grpc_channel_params,
    const boost::optional<GossipPropagationStrategyParams>
        &opt_mst_gossip_params,
    boost::optional<IrohadConfig::InterPeerTls> inter_peer_tls_config)
    : config_(config),
      listen_ip_(listen_ip),
      keypair_(keypair),
      startup_wsv_sync_policy_(startup_wsv_sync_policy),
      maybe_grpc_channel_params_(std::move(maybe_grpc_channel_params)),
      opt_mst_gossip_params_(opt_mst_gossip_params),
      inter_peer_tls_config_(std::move(inter_peer_tls_config)),
      pg_opt_(std::move(pg_opt)),
      rdb_opt_(std::move(rdb_opt)),
      subscription_engine_(getSubscription()),
      ordering_init(std::make_shared<ordering::OnDemandOrderingInit>(
          logger_manager->getLogger())),
      yac_init(std::make_shared<iroha::consensus::yac::YacInit>()),
      log_manager_(std::move(logger_manager)),
      log_(log_manager_->getLogger()) {
  log_->info("created");
  // TODO: rework in a more C++11+ - ish way luckychess 29.06.2019 IR-575
  std::srand(std::time(0));
  // Initializing storage at this point in order to insert genesis block before
  // initialization of iroha daemon

  if (auto e = expected::resultToOptionalError(initPendingTxsStorage() | [&] {

        return initStorage(
            startup_wsv_data_policy,
            config_.database_config
                    && config_.database_config->type == kDbTypeRocksdb
                ? StorageType::kRocksDb
                : StorageType::kPostgres);
      })) {
    log_->error("Storage initialization failed: {}", e.value());
  }
  #if defined(USE_BURROW)
        // create and pass burrow storage here
        vm_caller_ = std::make_unique<iroha::ametsuchi::BurrowVmCaller>();
  #endif
}

Irohad::~Irohad() {
  if (consensus_gate) {
    consensus_gate->stop();
  }
  if (ordering_gate) {
    ordering_gate->stop();
  }
  subscription_engine_->dispose();
}

/**
 * Initializing iroha daemon
 */
Irohad::RunResult Irohad::init() {
  IROHA_EXPECTED_ERROR_CHECK(initSettings());
  IROHA_EXPECTED_ERROR_CHECK(initValidatorsConfigs());
  IROHA_EXPECTED_ERROR_CHECK(initBatchParser());
  IROHA_EXPECTED_ERROR_CHECK(initValidators());
  // Recover WSV from the existing ledger to be sure it is consistent
  IROHA_EXPECTED_ERROR_CHECK(initWsvRestorer());
  IROHA_EXPECTED_ERROR_CHECK(restoreWsv());
  IROHA_EXPECTED_ERROR_CHECK(validateKeypair());
  IROHA_EXPECTED_ERROR_CHECK(initTlsCredentials());
  IROHA_EXPECTED_ERROR_CHECK(initPeerCertProvider());
  IROHA_EXPECTED_ERROR_CHECK(initClientFactory());
  IROHA_EXPECTED_ERROR_CHECK(initCryptoProvider());
  IROHA_EXPECTED_ERROR_CHECK(initNetworkClient());
  IROHA_EXPECTED_ERROR_CHECK(initFactories());
  IROHA_EXPECTED_ERROR_CHECK(initPersistentCache());
  IROHA_EXPECTED_ERROR_CHECK(initOrderingGate());
  IROHA_EXPECTED_ERROR_CHECK(initSimulator());
  IROHA_EXPECTED_ERROR_CHECK(initConsensusCache());
  IROHA_EXPECTED_ERROR_CHECK(initBlockLoader());
  IROHA_EXPECTED_ERROR_CHECK(initConsensusGate());
  IROHA_EXPECTED_ERROR_CHECK(initSynchronizer());
  IROHA_EXPECTED_ERROR_CHECK(initPeerCommunicationService());
  IROHA_EXPECTED_ERROR_CHECK(initStatusBus());
  IROHA_EXPECTED_ERROR_CHECK(initMstProcessor());
  IROHA_EXPECTED_ERROR_CHECK(initPendingTxsStorageWithCache());
  // Torii
  IROHA_EXPECTED_ERROR_CHECK(initTransactionCommandService());
  IROHA_EXPECTED_ERROR_CHECK(initQueryService());
  return {};
}

Irohad::RunResult Irohad::dropStorage() {
  IROHA_EXPECTED_ERROR_CHECK(storage->dropBlockStorage());
  IROHA_EXPECTED_ERROR_CHECK(resetWsv());
  return {};
}

Irohad::RunResult Irohad::resetWsv() {
  storage.reset();
  db_context_.reset();

  log_->info("Recreating schema.");
  return initStorage(
      StartupWsvDataPolicy::kDrop,
      config_.database_config && config_.database_config->type == kDbTypeRocksdb
          ? StorageType::kRocksDb
          : StorageType::kPostgres);
}

/**
 * Initializing setting query
 */
Irohad::RunResult Irohad::initSettings() {
  auto settingsQuery = storage->createSettingQuery();
  if (not settingsQuery) {
    return expected::makeError("Unable to create Settings");
  }

  IROHA_EXPECTED_TRY_GET_VALUE(settings, settingsQuery.get()->get());
  settings_ = std::move(settings);
  log_->info("[Init] => settings");
  return {};
}

/**
 * Initializing validators' configs
 */
Irohad::RunResult Irohad::initValidatorsConfigs() {
  validators_config_ =
      std::make_shared<shared_model::validation::ValidatorsConfig>(
          config_.max_proposal_size);
  block_validators_config_ =
      std::make_shared<shared_model::validation::ValidatorsConfig>(
          config_.max_proposal_size, true);
  proposal_validators_config_ =
      std::make_shared<shared_model::validation::ValidatorsConfig>(
          config_.max_proposal_size, false, true);
  log_->info("[Init] => validators configs");
  return {};
}

/**
 * Initializing iroha daemon storage
 */
Irohad::RunResult Irohad::initStorage(
    StartupWsvDataPolicy startup_wsv_data_policy, iroha::StorageType type) {
  query_response_factory_ =
      std::make_shared<shared_model::proto::ProtoQueryResponseFactory>();

  

  auto storage_creator = [&]() -> RunResult {
    auto process_block =
        [this](std::shared_ptr<shared_model::interface::Block const> block) {
          iroha::getSubscription()->notify(EventTypes::kOnBlock, block);
          if (ordering_init and tx_processor and pending_txs_storage_
              and mst_storage) {
            ordering_init->processCommittedBlock(block);
            tx_processor->processCommit(block);
            for (auto const &completed_tx : block->transactions()) {
              pending_txs_storage_->removeTransaction(completed_tx.hash());
              mst_storage->processFinalizedTransaction(completed_tx.hash());
            }
            for (auto const &rejected_tx_hash :
                 block->rejected_transactions_hashes()) {
              pending_txs_storage_->removeTransaction(rejected_tx_hash);
              mst_storage->processFinalizedTransaction(rejected_tx_hash);
            }
          }
        };

    auto st = type == StorageType::kPostgres
        ? ::iroha::initStorage(*pg_opt_,
                               pool_wrapper_,
                               pending_txs_storage_,
                               query_response_factory_,
                               config_.block_store_path,
                               vm_caller_ref,
                               process_block,
                               log_manager_->getChild("Storage"))
        : type == StorageType::kRocksDb
            ? ::iroha::initStorage(db_context_,
                                   pending_txs_storage_,
                                   query_response_factory_,
                                   config_.block_store_path,
                                   vm_caller_ref,
                                   process_block,
                                   log_manager_->getChild("Storage"))
            : iroha::expected::makeError("Unexpected storage type.");

    return st | [&](auto &&v) -> RunResult {
      storage = std::move(v);

      log_->info("[Init] => storage");
      return {};
    };
  };

  switch (type) {
    case StorageType::kPostgres: {
      IROHA_EXPECTED_TRY_GET_VALUE(
          pool_wrapper,
          PgConnectionInit::init(
              startup_wsv_data_policy, *pg_opt_, log_manager_));
      pool_wrapper_ = std::move(pool_wrapper);
    } break;

    case StorageType::kRocksDb: {
      IROHA_EXPECTED_TRY_GET_VALUE(
          rdb_port,
          RdbConnectionInit::init(
              startup_wsv_data_policy, *rdb_opt_, log_manager_));

      auto cache = std::make_shared<DatabaseCache<std::string>>();
      cache->addCacheblePath(RDB_ROOT /**/ RDB_WSV /**/ RDB_NETWORK);
      cache->addCacheblePath(RDB_ROOT /**/ RDB_WSV /**/ RDB_SETTINGS);
      cache->addCacheblePath(RDB_ROOT /**/ RDB_WSV /**/ RDB_ROLES);
      cache->addCacheblePath(RDB_ROOT /**/ RDB_WSV /**/ RDB_DOMAIN);

      db_context_ = std::make_shared<ametsuchi::RocksDBContext>(
          std::move(rdb_port), std::move(cache));
    } break;

    default:
      return iroha::expected::makeError<std::string>(
          "Unexpected storage type!");
  }
  std::optional<std::reference_wrapper<const iroha::ametsuchi::VmCaller>>
      vm_caller_ref;
  if (vm_caller_) {
    vm_caller_.setDbConnection(connection from pool wrapper)
    vm_caller_ref = *vm_caller_.value();
  }
  return storage_creator();
}

Irohad::RunResult Irohad::restoreWsv() {
  IROHA_EXPECTED_TRY_GET_VALUE(
      ledger_state,
      wsv_restorer_->restoreWsv(
          *storage,
          startup_wsv_sync_policy_
              == StartupWsvSynchronizationPolicy::kWaitForNewBlocks));
  assert(ledger_state);
  if (ledger_state->ledger_peers.empty()) {
    return iroha::expected::makeError<std::string>(
        "Have no peers in WSV after restoration!");
  }
  return {};
}

Irohad::RunResult Irohad::validateKeypair() {
  BOOST_ASSERT_MSG(keypair_.has_value(), "keypair must be specified somewhere");

  auto peers = storage->createPeerQuery() | [this](auto &&peer_query) {
    return peer_query->getLedgerPeerByPublicKey(
        PublicKeyHexStringView{keypair_->publicKey()});
  };
  if (not peers) {
    log_->warn("There is no peer in the ledger with my public key!");
  }

  return {};
}

/**
 * Initializing own TLS credentials.
 */
Irohad::RunResult Irohad::initTlsCredentials() {
  const auto &p2p_path = inter_peer_tls_config_ |
      [](const auto &p2p_config) { return p2p_config.my_tls_creds_path; };
  const auto &torii_path =
      config_.torii_tls_params | [](const auto &torii_config) {
        return boost::make_optional(torii_config.key_path);
      };

  auto load_tls_creds = [this](const auto &opt_path,
                               const auto &description,
                               auto &destination) -> RunResult {
    if (opt_path) {
      return TlsCredentials::load(opt_path.value()) |
                 [&](auto &&tls_creds) -> RunResult {
        destination = std::move(tls_creds);
        return {};
        log_->debug("Loaded my {} TLS credentials from '{}'.",
                    description,
                    opt_path.value());
      };
    }
    return {};
  };

  return load_tls_creds(p2p_path, "inter peer", my_inter_peer_tls_creds_) |
      [&, this] {
        return load_tls_creds(torii_path, "torii", this->torii_tls_creds_);
      };
}

/**
 * Initializing peers' certificates provider.
 */
Irohad::RunResult Irohad::initPeerCertProvider() {
  using namespace iroha::expected;

  if (not inter_peer_tls_config_) {
    return {};
  }

  using OptionalPeerCertProvider =
      boost::optional<std::unique_ptr<const PeerTlsCertificatesProvider>>;
  using PeerCertProviderResult = Result<OptionalPeerCertProvider, std::string>;

  return iroha::visit_in_place(
             inter_peer_tls_config_->peer_certificates,
             [this](const IrohadConfig::InterPeerTls::RootCert &root)
                 -> PeerCertProviderResult {
               return readTextFile(root.path) |
                   [&root, this](std::string &&root_cert) {
                     log_->debug("Loaded root TLS certificate from '{}'.",
                                 root.path);
                     return OptionalPeerCertProvider{
                         std::make_unique<PeerTlsCertificatesProviderRoot>(
                             root_cert)};
                   };
             },
             [this](const IrohadConfig::InterPeerTls::FromWsv &)
                 -> PeerCertProviderResult {
               auto opt_peer_query = this->storage->createPeerQuery();
               if (not opt_peer_query) {
                 return makeError(std::string{"Failed to get peer query."});
               }
               log_->debug("Prepared WSV peer certificate provider.");
               return boost::make_optional(
                   std::make_unique<PeerTlsCertificatesProviderWsv>(
                       std::move(opt_peer_query).value()));
             },
             [this](const IrohadConfig::InterPeerTls::None &)
                 -> PeerCertProviderResult {
               log_->debug("Peer certificate provider not initialized.");
               return OptionalPeerCertProvider{};
             },
             [](const auto &) -> PeerCertProviderResult {
               return makeError("Unimplemented peer certificate provider.");
             })
             | [this](OptionalPeerCertProvider &&opt_peer_cert_provider)
             -> RunResult {
    this->peer_tls_certificates_provider_ = std::move(opt_peer_cert_provider);
    return {};
  };
}

/**
 * Initializing channel pool.
 */
Irohad::RunResult Irohad::initClientFactory() {
  auto channel_factory =
      std::make_unique<ChannelFactory>(this->maybe_grpc_channel_params_);
  auto channel_pool = std::make_unique<ChannelPool>(std::move(channel_factory));
  inter_peer_client_factory_ =
      std::make_unique<GenericClientFactory>(std::move(channel_pool));
  return {};
}

/**
 * Initializing crypto provider
 */
Irohad::RunResult Irohad::initCryptoProvider() {
  crypto_signer_ =
      std::make_shared<shared_model::crypto::CryptoModelSigner<>>(*keypair_);

  log_->info("[Init] => crypto provider");
  return {};
}

Irohad::RunResult Irohad::initBatchParser() {
  batch_parser =
      std::make_shared<shared_model::interface::TransactionBatchParserImpl>();

  log_->info("[Init] => transaction batch parser");
  return {};
}

/**
 * Initializing validators
 */
Irohad::RunResult Irohad::initValidators() {
  auto factory = std::make_unique<shared_model::proto::ProtoProposalFactory<
      shared_model::validation::DefaultProposalValidator>>(validators_config_);
  auto validators_log_manager = log_manager_->getChild("Validators");
  stateful_validator = std::make_shared<StatefulValidatorImpl>(
      std::move(factory),
      batch_parser,
      validators_log_manager->getChild("Stateful")->getLogger());
  chain_validator = std::make_shared<ChainValidatorImpl>(
      getSupermajorityChecker(kConsensusConsistencyModel),
      validators_log_manager->getChild("Chain")->getLogger());

  log_->info("[Init] => validators");
  return {};
}

/**
 * Initializing network client
 */
Irohad::RunResult Irohad::initNetworkClient() {
  async_call_ =
      std::make_shared<network::AsyncGrpcClient<google::protobuf::Empty>>(
          log_manager_->getChild("AsyncNetworkClient")->getLogger());
  return {};
}

Irohad::RunResult Irohad::initFactories() {
  // proposal factory
  std::shared_ptr<
      shared_model::validation::AbstractValidator<iroha::protocol::Transaction>>
      proto_transaction_validator = std::make_shared<
          shared_model::validation::ProtoTransactionValidator>();
  std::unique_ptr<shared_model::validation::AbstractValidator<
      shared_model::interface::Proposal>>
      proposal_validator =
          std::make_unique<shared_model::validation::DefaultProposalValidator>(
              proposal_validators_config_);
  std::unique_ptr<
      shared_model::validation::AbstractValidator<iroha::protocol::Proposal>>
      proto_proposal_validator =
          std::make_unique<shared_model::validation::ProtoProposalValidator>(
              proto_transaction_validator);
  proposal_factory =
      std::make_shared<shared_model::proto::ProtoTransportFactory<
          shared_model::interface::Proposal,
          shared_model::proto::Proposal>>(std::move(proposal_validator),
                                          std::move(proto_proposal_validator));

  auto batch_validator =
      std::make_shared<shared_model::validation::DefaultBatchValidator>(
          validators_config_);
  // transaction factories
  transaction_batch_factory_ =
      std::make_shared<shared_model::interface::TransactionBatchFactoryImpl>(
          batch_validator);

  std::unique_ptr<shared_model::validation::AbstractValidator<
      shared_model::interface::Transaction>>
      transaction_validator = std::make_unique<
          shared_model::validation::DefaultOptionalSignedTransactionValidator>(
          validators_config_);
  transaction_factory =
      std::make_shared<shared_model::proto::ProtoTransportFactory<
          shared_model::interface::Transaction,
          shared_model::proto::Transaction>>(
          std::move(transaction_validator),
          std::move(proto_transaction_validator));

  // query factories
  std::unique_ptr<shared_model::validation::AbstractValidator<
      shared_model::interface::Query>>
      query_validator = std::make_unique<
          shared_model::validation::DefaultSignedQueryValidator>(
          validators_config_);
  std::unique_ptr<
      shared_model::validation::AbstractValidator<iroha::protocol::Query>>
      proto_query_validator =
          std::make_unique<shared_model::validation::ProtoQueryValidator>();
  query_factory = std::make_shared<
      shared_model::proto::ProtoTransportFactory<shared_model::interface::Query,
                                                 shared_model::proto::Query>>(
      std::move(query_validator), std::move(proto_query_validator));

  auto blocks_query_validator = std::make_unique<
      shared_model::validation::DefaultSignedBlocksQueryValidator>(
      validators_config_);
  auto proto_blocks_query_validator =
      std::make_unique<shared_model::validation::ProtoBlocksQueryValidator>();

  blocks_query_factory =
      std::make_shared<shared_model::proto::ProtoTransportFactory<
          shared_model::interface::BlocksQuery,
          shared_model::proto::BlocksQuery>>(
          std::move(blocks_query_validator),
          std::move(proto_blocks_query_validator));

  log_->info("[Init] => factories");
  return {};
}

/**
 * Initializing persistent cache
 */
Irohad::RunResult Irohad::initPersistentCache() {
  persistent_cache = std::make_shared<TxPresenceCacheImpl>(storage);

  log_->info("[Init] => persistent cache");
  return {};
}

Irohad::RunResult Irohad::initPendingTxsStorageWithCache() {
  pending_txs_storage_->insertPresenceCache(persistent_cache);
  return {};
}

/**
 * Initializing ordering gate
 */
Irohad::RunResult Irohad::initOrderingGate() {
  auto block_query = storage->createBlockQuery();
  if (not block_query) {
    return iroha::expected::makeError<std::string>(
        "Failed to create block query");
  }

  auto factory = std::make_unique<shared_model::proto::ProtoProposalFactory<
      shared_model::validation::DefaultProposalValidator>>(validators_config_);

  ordering_gate = ordering_init->initOrderingGate(
      config_.max_proposal_size,
      std::chrono::milliseconds(config_.proposal_delay),
      transaction_factory,
      batch_parser,
      transaction_batch_factory_,
      std::move(factory),
      proposal_factory,
      persistent_cache,
      log_manager_->getChild("Ordering"),
      inter_peer_client_factory_,
      std::chrono::milliseconds(
          config_.proposal_creation_timeout.value_or(kMaxRoundsDelayDefault)));
  log_->info("[Init] => init ordering gate - [{}]",
             logger::boolRepr(bool(ordering_gate)));
  return {};
}

/**
 * Initializing iroha verified proposal creator and block creator
 */
Irohad::RunResult Irohad::initSimulator() {
  IROHA_EXPECTED_TRY_GET_VALUE(command_executor,
                               storage->createCommandExecutor());
  auto block_factory = std::make_unique<shared_model::proto::ProtoBlockFactory>(
      //  Block factory in simulator uses UnsignedBlockValidator because
      //  it is not required to check signatures of block here, as they
      //  will be checked when supermajority of peers will sign the block.
      //  It is also not required to validate signatures of transactions
      //  here because they are validated in the ordering gate, where they
      //  are received from the ordering service.
      std::make_unique<shared_model::validation::DefaultUnsignedBlockValidator>(
          block_validators_config_),
      std::make_unique<shared_model::validation::ProtoBlockValidator>());

  simulator = std::make_shared<Simulator>(
      std::move(command_executor),
      stateful_validator,
      storage,
      crypto_signer_,
      std::move(block_factory),
      log_manager_->getChild("Simulator")->getLogger());

  log_->info("[Init] => init simulator");
  return {};
}

/**
 * Initializing consensus block cache
 */
Irohad::RunResult Irohad::initConsensusCache() {
  consensus_result_cache_ = std::make_shared<consensus::ConsensusResultCache>();

  log_->info("[Init] => init consensus block cache");
  return {};
}

/**
 * Initializing block loader
 */
Irohad::RunResult Irohad::initBlockLoader() {
  block_loader =
      loader_init.initBlockLoader(storage,
                                  storage,
                                  consensus_result_cache_,
                                  block_validators_config_,
                                  log_manager_->getChild("BlockLoader"),
                                  inter_peer_client_factory_);

  log_->info("[Init] => block loader");
  return {};
}

/**
 * Initializing consensus gate
 */
Irohad::RunResult Irohad::initConsensusGate() {
  auto initial_ledger_state = storage->getLedgerState();
  if (not initial_ledger_state) {
    return expected::makeError("Failed to fetch ledger state!");
  }

  consensus_gate = yac_init->initConsensusGate(
      {initial_ledger_state.value()->top_block_info.height + 1,
       ordering::kFirstRejectRound},
      config_.initial_peers,
      *initial_ledger_state,
      block_loader,
      *keypair_,
      consensus_result_cache_,
      std::chrono::milliseconds(config_.vote_delay),
      kConsensusConsistencyModel,
      log_manager_->getChild("Consensus"),
      inter_peer_client_factory_);
  log_->info("[Init] => consensus gate");
  return {};
}

/**
 * Initializing synchronizer
 */
Irohad::RunResult Irohad::initSynchronizer() {
  IROHA_EXPECTED_TRY_GET_VALUE(command_executor,
                               storage->createCommandExecutor());
  synchronizer = std::make_shared<SynchronizerImpl>(
      std::move(command_executor),
      chain_validator,
      storage,
      storage,
      block_loader,
      log_manager_->getChild("Synchronizer")->getLogger());

  log_->info("[Init] => synchronizer");
  return {};
}

namespace {
  void printSynchronizationEvent(
      logger::LoggerPtr log, synchronizer::SynchronizationEvent const &event) {
    using iroha::synchronizer::SynchronizationOutcomeType;
    switch (event.sync_outcome) {
      case SynchronizationOutcomeType::kCommit:
        log->info(R"(~~~~~~~~~| COMMIT =^._.^= |~~~~~~~~~ )");
        break;
      case SynchronizationOutcomeType::kReject:
        log->info(R"(~~~~~~~~~| REJECT \(*.*)/ |~~~~~~~~~ )");
        break;
      case SynchronizationOutcomeType::kNothing:
        log->info(R"(~~~~~~~~~| EMPTY (-_-)zzz |~~~~~~~~~ )");
        break;
    }
  }
}  // namespace

/**
 * Initializing peer communication service
 */
Irohad::RunResult Irohad::initPeerCommunicationService() {
  pcs = std::make_shared<PeerCommunicationServiceImpl>(
      ordering_gate,
      log_manager_->getChild("PeerCommunicationService")->getLogger());

  log_->info("[Init] => pcs");
  return {};
}

Irohad::RunResult Irohad::initStatusBus() {
  struct StatusBusImpl final : public StatusBus {
    StatusBusImpl(Irohad &irohad) : irohad_(irohad) {}

    void publish(StatusBus::Objects const &response) override {
      iroha::getSubscription()->notify(EventTypes::kOnTransactionResponse,
                                       StatusBus::Objects(response));
      if (irohad_.command_service)
        irohad_.command_service->processTransactionResponse(response);
    }

   private:
    Irohad &irohad_;
  };
  status_bus_ = std::make_shared<StatusBusImpl>(*this);
  log_->info("[Init] => Tx status bus");
  return {};
}

Irohad::RunResult Irohad::initMstProcessor() {
  auto mst_logger_manager =
      log_manager_->getChild("MultiSignatureTransactions");
  auto mst_state_logger = mst_logger_manager->getChild("State")->getLogger();
  auto mst_completer = std::make_shared<DefaultCompleter>(std::chrono::minutes(
      config_.mst_expiration_time.value_or(kMstExpirationTimeDefault)));
  mst_storage = std::make_shared<MstStorageStateImpl>(
      mst_completer,
      mst_state_logger,
      mst_logger_manager->getChild("Storage")->getLogger());
  std::shared_ptr<iroha::PropagationStrategy> mst_propagation;
  if (config_.mst_support) {
    mst_transport = std::make_shared<iroha::network::MstTransportGrpc>(
        async_call_,
        transaction_factory,
        batch_parser,
        transaction_batch_factory_,
        persistent_cache,
        mst_completer,
        PublicKeyHexStringView{keypair_->publicKey()},
        std::move(mst_state_logger),
        mst_logger_manager->getChild("Transport")->getLogger(),
        std::make_unique<iroha::network::ClientFactoryImpl<
            iroha::network::MstTransportGrpc::Service>>(
            inter_peer_client_factory_));
    mst_propagation = std::make_shared<GossipPropagationStrategy>(
        storage, rxcpp::observe_on_new_thread(), *opt_mst_gossip_params_);
  } else {
    mst_transport = std::make_shared<iroha::network::MstTransportStub>();
    mst_propagation = std::make_shared<iroha::PropagationStrategyStub>();
  }

  auto mst_time = std::make_shared<MstTimeProviderImpl>();
  auto fair_mst_processor = std::make_shared<FairMstProcessor>(
      mst_transport,
      mst_storage,
      mst_propagation,
      mst_time,
      mst_logger_manager->getChild("Processor")->getLogger());
  mst_processor = fair_mst_processor;
  mst_transport->subscribe(fair_mst_processor);

  log_->info("[Init] => MST processor");
  return {};
}

Irohad::RunResult Irohad::initPendingTxsStorage() {
  pending_txs_storage_ = std::make_shared<PendingTransactionStorageImpl>();
  log_->info("[Init] => pending transactions storage");
  return {};
}

/**
 * Initializing transaction command service
 */
Irohad::RunResult Irohad::initTransactionCommandService() {
  auto command_service_log_manager = log_manager_->getChild("CommandService");
  auto status_factory =
      std::make_shared<shared_model::proto::ProtoTxStatusFactory>();
  auto cs_cache = std::make_shared<::torii::CommandServiceImpl::CacheType>();
  tx_processor = std::make_shared<TransactionProcessorImpl>(
      pcs,
      mst_processor,
      status_bus_,
      status_factory,
      command_service_log_manager->getChild("Processor")->getLogger());
  mst_processor->onStateUpdate().subscribe(
      [tx_processor(utils::make_weak(tx_processor)),
       pending_txs_storage(utils::make_weak(pending_txs_storage_))](
          std::shared_ptr<MstState> const &state) {
        auto maybe_tx_processor = tx_processor.lock();
        auto maybe_pending_txs_storage = pending_txs_storage.lock();
        if (maybe_tx_processor and maybe_pending_txs_storage) {
          maybe_tx_processor->processStateUpdate(state);
          maybe_pending_txs_storage->updatedBatchesHandler(state);
        }
      });
  mst_processor->onPreparedBatches().subscribe(
      [tx_processor(utils::make_weak(tx_processor)),
       pending_txs_storage(utils::make_weak(pending_txs_storage_))](
          std::shared_ptr<shared_model::interface::TransactionBatch> const
              &batch) {
        auto maybe_tx_processor = tx_processor.lock();
        auto maybe_pending_txs_storage = pending_txs_storage.lock();
        if (maybe_tx_processor and maybe_pending_txs_storage) {
          maybe_tx_processor->processPreparedBatch(batch);
          maybe_pending_txs_storage->removeBatch(batch);
        }
      });
  mst_processor->onExpiredBatches().subscribe(
      [tx_processor(utils::make_weak(tx_processor)),
       pending_txs_storage(utils::make_weak(pending_txs_storage_))](
          std::shared_ptr<shared_model::interface::TransactionBatch> const
              &batch) {
        auto maybe_tx_processor = tx_processor.lock();
        auto maybe_pending_txs_storage = pending_txs_storage.lock();
        if (maybe_tx_processor and maybe_pending_txs_storage) {
          maybe_tx_processor->processExpiredBatch(batch);
          maybe_pending_txs_storage->removeBatch(batch);
        }
      });
  command_service = std::make_shared<::torii::CommandServiceImpl>(
      tx_processor,
      status_bus_,
      status_factory,
      cs_cache,
      persistent_cache,
      command_service_log_manager->getLogger());
  command_service_transport =
      std::make_shared<::torii::CommandServiceTransportGrpc>(
          command_service,
          status_bus_,
          status_factory,
          transaction_factory,
          batch_parser,
          transaction_batch_factory_,
          config_.stale_stream_max_rounds.value_or(
              kStaleStreamMaxRoundsDefault),
          command_service_log_manager->getChild("Transport")->getLogger());

  log_->info("[Init] => command service");
  return {};
}

/**
 * Initializing query command service
 */
Irohad::RunResult Irohad::initQueryService() {
  auto query_service_log_manager = log_manager_->getChild("QueryService");
  auto query_processor = std::make_shared<QueryProcessorImpl>(
      storage,
      storage,
      pending_txs_storage_,
      query_response_factory_,
      query_service_log_manager->getChild("Processor")->getLogger());

  query_service = std::make_shared<::torii::QueryService>(
      query_processor,
      query_factory,
      blocks_query_factory,
      query_service_log_manager->getLogger());

  log_->info("[Init] => query service");
  return {};
}

Irohad::RunResult Irohad::initWsvRestorer() {
  auto interface_validator =
      std::make_unique<shared_model::validation::DefaultSignedBlockValidator>(
          block_validators_config_);
  auto proto_validator =
      std::make_unique<shared_model::validation::ProtoBlockValidator>();
  wsv_restorer_ = std::make_shared<iroha::ametsuchi::WsvRestorerImpl>(
      std::move(interface_validator),
      std::move(proto_validator),
      chain_validator,
      log_manager_->getChild("WsvRestorer")->getLogger());
  return {};
}

namespace {
  struct ProcessGateObjectContext {
    std::shared_ptr<iroha::synchronizer::Synchronizer> synchronizer;
    std::shared_ptr<iroha::ordering::OnDemandOrderingInit> ordering_init;
    std::shared_ptr<iroha::consensus::yac::YacInit> yac_init;
    logger::LoggerPtr log;
    std::shared_ptr<iroha::Subscription> subscription;
  };

  void processGateObject(ProcessGateObjectContext context,
                         consensus::GateObject const &object) {
    context.subscription->notify(
        EventTypes::kOnConsensusGateEvent,
        ::torii::CommandServiceTransportGrpc::ConsensusGateEvent{});
    context.log->info("~~~~~~~~~| PROPOSAL ^_^ |~~~~~~~~~ ");
    auto event = context.synchronizer->processOutcome(std::move(object));
    if (not event) {
      return;
    }
    context.subscription->notify(EventTypes::kOnSynchronization,
                                 SynchronizationEvent(*event));
    printSynchronizationEvent(context.log, *event);
    auto round_switch =
        context.ordering_init->processSynchronizationEvent(std::move(*event));
    if (auto maybe_object = context.yac_init->processRoundSwitch(
            round_switch.next_round, round_switch.ledger_state)) {
      auto round = [](auto &object) { return object.round; };
      context.log->info("Ignoring object with {} because {} is newer",
                        std::visit(round, object),
                        std::visit(round, *maybe_object));
      return processGateObject(std::move(context), *maybe_object);
    }
    context.ordering_init->processRoundSwitch(round_switch);
  }
}  // namespace

/**
 * Run iroha daemon
 */
Irohad::RunResult Irohad::run() {
  ordering_init->subscribe([simulator(utils::make_weak(simulator)),
                            consensus_gate(utils::make_weak(consensus_gate)),
                            tx_processor(utils::make_weak(tx_processor)),
                            subscription(utils::make_weak(getSubscription()))](
                               network::OrderingEvent const &event) {
    auto maybe_simulator = simulator.lock();
    auto maybe_consensus_gate = consensus_gate.lock();
    auto maybe_tx_processor = tx_processor.lock();
    auto maybe_subscription = subscription.lock();
    if (maybe_simulator and maybe_consensus_gate and maybe_tx_processor
        and maybe_subscription) {
      maybe_subscription->notify(EventTypes::kOnProposal, event);
      auto verified_proposal = maybe_simulator->processProposal(event);
      maybe_subscription->notify(EventTypes::kOnVerifiedProposal,
                                 verified_proposal);
      maybe_tx_processor->processVerifiedProposalCreatorEvent(
          verified_proposal);
      auto block = maybe_simulator->processVerifiedProposal(
          std::move(verified_proposal));
      maybe_consensus_gate->vote(std::move(block));
    }
  });

  yac_init->subscribe([synchronizer(utils::make_weak(synchronizer)),
                       ordering_init(utils::make_weak(ordering_init)),
                       yac_init(utils::make_weak(yac_init)),
                       log(utils::make_weak(log_)),
                       subscription(utils::make_weak(getSubscription()))](
                          consensus::GateObject const &object) {
    auto maybe_synchronizer = synchronizer.lock();
    auto maybe_ordering_init = ordering_init.lock();
    auto maybe_yac_init = yac_init.lock();
    auto maybe_log = log.lock();
    auto maybe_subscription = subscription.lock();
    if (maybe_synchronizer and maybe_ordering_init and maybe_yac_init
        and maybe_log and maybe_subscription) {
      processGateObject({std::move(maybe_synchronizer),
                         std::move(maybe_ordering_init),
                         std::move(maybe_yac_init),
                         std::move(maybe_log),
                         std::move(maybe_subscription)},
                        object);
    }
  });

  // Initializing torii server
  torii_server = std::make_unique<ServerRunner>(
      listen_ip_ + ":" + std::to_string(config_.torii_port),
      log_manager_->getChild("ToriiServerRunner")->getLogger(),
      false);

  // Initializing internal server
  internal_server = std::make_unique<ServerRunner>(
      listen_ip_ + ":" + std::to_string(config_.internal_port),
      log_manager_->getChild("InternalServerRunner")->getLogger(),
      false);

  // Run torii server
  IROHA_EXPECTED_TRY_GET_VALUE(torii_port,
                               torii_server->append(command_service_transport)
                                   .append(query_service)
                                   .run());
  log_->info("Torii server bound on port {}", torii_port);

  // Run torii TLS server
  if (torii_tls_creds_) {
    torii_tls_server = std::make_unique<ServerRunner>(
        listen_ip_ + ":" + std::to_string(config_.torii_tls_params->port),
        log_manager_->getChild("ToriiTlsServerRunner")->getLogger(),
        false,
        *torii_tls_creds_);
    IROHA_EXPECTED_TRY_GET_VALUE(torii_tls_port,
                                 torii_tls_server.value()
                                     ->append(command_service_transport)
                                     .append(query_service)
                                     .run());
    log_->info("Torii TLS server bound on port {}", torii_tls_port);
  }

  // Run internal server
  if (config_.mst_support) {
    internal_server->append(
        std::static_pointer_cast<MstTransportGrpc>(mst_transport));
  }
  IROHA_EXPECTED_TRY_GET_VALUE(internal_port,
                               internal_server->append(ordering_init->service)
                                   .append(yac_init->getConsensusNetwork())
                                   .append(loader_init.service)
                                   .run());
  log_->info("Internal server bound on port {}", internal_port);

  log_->info("===> iroha initialized");
  // initiate first round
  auto block_query = storage->createBlockQuery();
  if (not block_query) {
    return expected::makeError("Failed to create block query");
  }
  auto block_var =
      (*block_query)->getBlock((*block_query)->getTopBlockHeight());
  if (auto e = expected::resultToOptionalError(block_var)) {
    return expected::makeError("Failed to get the top block: " + e->message);
  }

  auto &block =
      boost::get<expected::ValueOf<decltype(block_var)>>(&block_var)->value;
  auto block_height = block->height();

  auto peers = storage->createPeerQuery() |
      [](auto &&peer_query) { return peer_query->getLedgerPeers(); };
  if (not peers) {
    return expected::makeError("Failed to fetch ledger peers!");
  }

  auto initial_ledger_state = storage->getLedgerState();
  if (not initial_ledger_state) {
    return expected::makeError("Failed to fetch ledger state!");
  }

  ordering_init->processCommittedBlock(std::move(block));

  subscription_engine_->dispatcher()->add(
      iroha::SubscriptionEngineHandlers::kYac,
      [synchronizer(utils::make_weak(synchronizer)),
       ordering_init(utils::make_weak(ordering_init)),
       yac_init(utils::make_weak(yac_init)),
       log(utils::make_weak(log_)),
       subscription(utils::make_weak(getSubscription())),
       block_height,
       initial_ledger_state] {
        auto maybe_synchronizer = synchronizer.lock();
        auto maybe_ordering_init = ordering_init.lock();
        auto maybe_yac_init = yac_init.lock();
        auto maybe_log = log.lock();
        auto maybe_subscription = subscription.lock();
        if (maybe_synchronizer and maybe_ordering_init and maybe_yac_init
            and maybe_log and maybe_subscription) {
          ProcessGateObjectContext context{std::move(maybe_synchronizer),
                                           std::move(maybe_ordering_init),
                                           std::move(maybe_yac_init),
                                           std::move(maybe_log),
                                           std::move(maybe_subscription)};
          consensus::Round initial_round{block_height,
                                         ordering::kFirstRejectRound};
          auto round_switch =
              context.ordering_init->processSynchronizationEvent(
                  {SynchronizationOutcomeType::kCommit,
                   initial_round,
                   *initial_ledger_state});
          if (auto maybe_object = context.yac_init->processRoundSwitch(
                  round_switch.next_round, round_switch.ledger_state)) {
            auto round = [](auto &object) { return object.round; };
            context.log->info("Ignoring object with {} because {} is newer",
                              initial_round,
                              std::visit(round, *maybe_object));
            return processGateObject(std::move(context), *maybe_object);
          }
          context.ordering_init->processRoundSwitch(round_switch);
        }
      });

  return {};
}
