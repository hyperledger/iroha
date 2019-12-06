/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/application.hpp"

#include <boost/filesystem.hpp>
#include <rxcpp/operators/rx-map.hpp>
#include "ametsuchi/impl/flat_file_block_storage.hpp"
#include "ametsuchi/impl/k_times_reconnection_strategy.hpp"
#include "ametsuchi/impl/pool_wrapper.hpp"
#include "ametsuchi/impl/postgres_block_storage_factory.hpp"
#include "ametsuchi/impl/storage_impl.hpp"
#include "ametsuchi/impl/tx_presence_cache_impl.hpp"
#include "ametsuchi/impl/wsv_restorer_impl.hpp"
#include "backend/protobuf/proto_block_json_converter.hpp"
#include "backend/protobuf/proto_permission_to_string.hpp"
#include "backend/protobuf/proto_proposal_factory.hpp"
#include "backend/protobuf/proto_query_response_factory.hpp"
#include "backend/protobuf/proto_transport_factory.hpp"
#include "backend/protobuf/proto_tx_status_factory.hpp"
#include "common/bind.hpp"
#include "consensus/yac/consistency_model.hpp"
#include "cryptography/crypto_provider/crypto_model_signer.hpp"
#include "generator/generator.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser_impl.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/impl/consensus_init.hpp"
#include "main/impl/pending_transaction_storage_init.hpp"
#include "main/impl/pg_connection_init.hpp"
#include "main/server_runner.hpp"
#include "multi_sig_transactions/gossip_propagation_strategy.hpp"
#include "multi_sig_transactions/mst_processor_impl.hpp"
#include "multi_sig_transactions/mst_propagation_strategy_stub.hpp"
#include "multi_sig_transactions/mst_time_provider_impl.hpp"
#include "multi_sig_transactions/storage/mst_storage_impl.hpp"
#include "multi_sig_transactions/transport/mst_transport_grpc.hpp"
#include "multi_sig_transactions/transport/mst_transport_stub.hpp"
#include "network/impl/block_loader_impl.hpp"
#include "network/impl/peer_communication_service_impl.hpp"
#include "network/impl/peer_tls_certificates_provider_root.hpp"
#include "network/impl/peer_tls_certificates_provider_wsv.hpp"
#include "network/impl/tls_credentials.hpp"
#include "ordering/impl/kick_out_proposal_creation_strategy.hpp"
#include "ordering/impl/on_demand_common.hpp"
#include "ordering/impl/on_demand_ordering_gate.hpp"
#include "simulator/impl/simulator.hpp"
#include "synchronizer/impl/synchronizer_impl.hpp"
#include "torii/impl/command_service_impl.hpp"
#include "torii/impl/command_service_transport_grpc.hpp"
#include "torii/impl/status_bus_impl.hpp"
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

using namespace iroha;
using namespace iroha::ametsuchi;
using namespace iroha::simulator;
using namespace iroha::validation;
using namespace iroha::network;
using namespace iroha::synchronizer;
using namespace iroha::torii;
using namespace iroha::consensus::yac;

using namespace std::chrono_literals;

/// Consensus consistency model type.
static constexpr iroha::consensus::yac::ConsistencyModel
    kConsensusConsistencyModel = iroha::consensus::yac::ConsistencyModel::kCft;

/**
 * Configuring iroha daemon
 */
Irohad::Irohad(
    const boost::optional<std::string> &block_store_dir,
    std::unique_ptr<ametsuchi::PostgresOptions> pg_opt,
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
    const boost::optional<GossipPropagationStrategyParams>
        &opt_mst_gossip_params,
    const boost::optional<iroha::torii::TlsParams> &torii_tls_params,
    boost::optional<IrohadConfig::InterPeerTls> inter_peer_tls_config)
    : block_store_dir_(block_store_dir),
      listen_ip_(listen_ip),
      torii_port_(torii_port),
      torii_tls_params_(torii_tls_params),
      internal_port_(internal_port),
      max_proposal_size_(max_proposal_size),
      proposal_delay_(proposal_delay),
      vote_delay_(vote_delay),
      is_mst_supported_(opt_mst_gossip_params),
      mst_expiration_time_(mst_expiration_time),
      max_rounds_delay_(max_rounds_delay),
      stale_stream_max_rounds_(stale_stream_max_rounds),
      opt_alternative_peers_(std::move(opt_alternative_peers)),
      opt_mst_gossip_params_(opt_mst_gossip_params),
      inter_peer_tls_config_(std::move(inter_peer_tls_config)),
      pending_txs_storage_init(
          std::make_unique<PendingTransactionStorageInit>()),
      keypair(keypair),
      ordering_init(logger_manager->getLogger()),
      yac_init(std::make_unique<iroha::consensus::yac::YacInit>()),
      consensus_gate_objects(consensus_gate_objects_lifetime),
      log_manager_(std::move(logger_manager)),
      log_(log_manager_->getLogger()) {
  log_->info("created");
  // TODO: rework in a more C++11+ - ish way luckychess 29.06.2019 IR-575
  std::srand(std::time(0));
  // Initializing storage at this point in order to insert genesis block before
  // initialization of iroha daemon

  if (auto e = expected::resultToOptionalError(initPendingTxsStorage() | [&] {
        return initStorage(std::move(pg_opt));
      })) {
    log_->error("Storage initialization failed: {}", e.value());
  }
}

Irohad::~Irohad() {
  consensus_gate_objects_lifetime.unsubscribe();
  consensus_gate_events_subscription.unsubscribe();
}

/**
 * Initializing iroha daemon
 */
Irohad::RunResult Irohad::init() {
  // clang-format off
  return initSettings()
  | [this]{ return initValidatorsConfigs();}
  | [this]{ return initWsvRestorer(); // Recover WSV from the existing ledger
                                      // to be sure it is consistent
  }
  | [this]{ return restoreWsv();}
  | [this]{ return validateKeypair();}
  | [this]{ return initTlsCredentials();}
  | [this]{ return initPeerCertProvider();}
  | [this]{ return initCryptoProvider();}
  | [this]{ return initBatchParser();}
  | [this]{ return initValidators();}
  | [this]{ return initNetworkClient();}
  | [this]{ return initFactories();}
  | [this]{ return initPersistentCache();}
  | [this]{ return initOrderingGate();}
  | [this]{ return initSimulator();}
  | [this]{ return initConsensusCache();}
  | [this]{ return initBlockLoader();}
  | [this]{ return initConsensusGate();}
  | [this]{ return initSynchronizer();}
  | [this]{ return initPeerCommunicationService();}
  | [this]{ return initStatusBus();}
  | [this]{ return initMstProcessor();}

  // Torii
  | [this]{ return initTransactionCommandService();}
  | [this]{ return initQueryService();};
  // clang-format on
}

/**
 * Dropping iroha daemon storage
 */
void Irohad::dropStorage() {
  storage->reset();
}

/**
 * Initializing setting query
 */
Irohad::RunResult Irohad::initSettings() {
  auto settingsQuery = storage->createSettingQuery();
  if (not settingsQuery) {
    return expected::makeError("Unable to create Settings");
  }

  return settingsQuery.get()->get() | [this](auto &&settings) -> RunResult {
    this->settings_ = std::move(settings);

    log_->info("[Init] => settings");
    return {};
  };
}

/**
 * Initializing validators' configs
 */
Irohad::RunResult Irohad::initValidatorsConfigs() {
  validators_config_ =
      std::make_shared<shared_model::validation::ValidatorsConfig>(
          max_proposal_size_, settings_);
  block_validators_config_ =
      std::make_shared<shared_model::validation::ValidatorsConfig>(
          max_proposal_size_, settings_, true);
  proposal_validators_config_ =
      std::make_shared<shared_model::validation::ValidatorsConfig>(
          max_proposal_size_, settings_, false, true);
  log_->info("[Init] => validators configs");
  return {};
}

/**
 * Initializing iroha daemon storage
 */
Irohad::RunResult Irohad::initStorage(
    std::unique_ptr<ametsuchi::PostgresOptions> pg_opt) {
  query_response_factory_ =
      std::make_shared<shared_model::proto::ProtoQueryResponseFactory>();
  auto perm_converter =
      std::make_shared<shared_model::proto::ProtoPermissionToString>();

  // TODO: luckychess IR-308 05.08.2019 stateless validation for genesis block
  auto block_transport_factory =
      std::make_shared<shared_model::proto::ProtoBlockFactory>(
          std::make_unique<shared_model::validation::AlwaysValidValidator<
              shared_model::interface::Block>>(),
          std::make_unique<shared_model::validation::ProtoBlockValidator>());

  boost::optional<std::string> string_res = boost::none;

  // create database if it does not exist
  PgConnectionInit::createDatabaseIfNotExist(*pg_opt).match(
      [](auto &&val) {},
      [&string_res](auto &&error) { string_res = error.error; });

  if (string_res) {
    return expected::makeError(string_res.value());
  }

  const int pool_size = 10;
  auto pool = PgConnectionInit::prepareConnectionPool(
      iroha::ametsuchi::KTimesReconnectionStrategyFactory{10},
      *pg_opt,
      pool_size,
      log_manager_);

  if (auto error = resultToOptionalError(pool)) {
    return expected::makeError(std::move(*error));
  }

  pool_wrapper_ = std::move(resultToOptionalValue(pool).value());

  std::unique_ptr<BlockStorageFactory> temporary_block_storage_factory =
      std::make_unique<PostgresBlockStorageFactory>(
          pool_wrapper_,
          block_transport_factory,
          []() { return generator::randomString(20); },
          log_manager_->getChild("TemporaryBlockStorage")->getLogger());

  std::unique_ptr<BlockStorage> persistent_block_storage;
  if (block_store_dir_) {
    auto flat_file = FlatFile::create(
        *block_store_dir_, log_manager_->getChild("FlatFile")->getLogger());
    if (not flat_file) {
      return expected::makeError(
          "Unable to create FlatFile for persistent storage");
    }
    std::shared_ptr<shared_model::interface::BlockJsonConverter>
        block_converter =
            std::make_shared<shared_model::proto::ProtoBlockJsonConverter>();
    persistent_block_storage = std::make_unique<FlatFileBlockStorage>(
        std::move(flat_file.get()),
        block_converter,
        log_manager_->getChild("FlatFileBlockStorage")->getLogger());
  } else {
    auto sql =
        std::make_unique<soci::session>(*pool_wrapper_->connection_pool_);
    const std::string persistent_table("blocks");

    auto create_table_result =
        PostgresBlockStorageFactory::createTable(*sql, persistent_table);
    if (boost::get<expected::Error<std::string>>(&create_table_result)) {
      return create_table_result;
    }
    persistent_block_storage = std::make_unique<PostgresBlockStorage>(
        pool_wrapper_, block_transport_factory, persistent_table, log_);
  }
  return StorageImpl::create(std::move(pg_opt),
                             pool_wrapper_,
                             perm_converter,
                             pending_txs_storage_,
                             query_response_factory_,
                             std::move(temporary_block_storage_factory),
                             std::move(persistent_block_storage),
                             log_manager_->getChild("Storage"))
             | [&](auto &&v) -> RunResult {
    storage = std::move(v);
    log_->info("[Init] => storage");
    return {};
  };
}

Irohad::RunResult Irohad::restoreWsv() {
  return wsv_restorer_->restoreWsv(*storage) |
             [](const auto &ledger_state) -> RunResult {
    assert(ledger_state);
    if (ledger_state->ledger_peers.empty()) {
      return iroha::expected::makeError<std::string>(
          "Have no peers in WSV after restoration!");
    }
    return {};
  };
}

Irohad::RunResult Irohad::validateKeypair() {
  auto peers = storage->createPeerQuery() | [this](auto &&peer_query) {
    return peer_query->getLedgerPeerByPublicKey(keypair.publicKey());
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
  const auto &torii_path = torii_tls_params_ | [](const auto &torii_config) {
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

  static const auto read_file =
      [](const std::string &path) -> Result<std::string, std::string> {
    try {
      std::ifstream certificate_file(path);
      std::stringstream ss;
      ss << certificate_file.rdbuf();
      return makeValue(ss.str());
    } catch (const std::exception &e) {
      return makeError(e.what());
    }
  };

  using OptionalPeerCertProvider =
      boost::optional<std::unique_ptr<const PeerTlsCertificatesProvider>>;
  using PeerCertProviderResult = Result<OptionalPeerCertProvider, std::string>;

  return iroha::visit_in_place(
             inter_peer_tls_config_->peer_certificates,
             [this](const IrohadConfig::InterPeerTls::RootCert &root)
                 -> PeerCertProviderResult {
               return read_file(root.path) |
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
 * Initializing crypto provider
 */
Irohad::RunResult Irohad::initCryptoProvider() {
  crypto_signer_ =
      std::make_shared<shared_model::crypto::CryptoModelSigner<>>(keypair);

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
      std::make_shared<shared_model::validation::BatchValidator>(
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

/**
 * Initializing ordering gate
 */
Irohad::RunResult Irohad::initOrderingGate() {
  auto block_query = storage->createBlockQuery();
  if (not block_query) {
    return iroha::expected::makeError<std::string>(
        "Failed to create block query");
  }
  // since delay is 2, it is required to get two more hashes from block store,
  // in addition to top block
  const size_t kNumBlocks = 3;
  auto top_height = (*block_query)->getTopBlockHeight();
  decltype(top_height) block_hashes =
      top_height > kNumBlocks ? kNumBlocks : top_height;

  auto hash_stub = shared_model::interface::types::HashType{std::string(
      shared_model::crypto::DefaultCryptoAlgorithmType::kHashLength, '0')};
  std::vector<shared_model::interface::types::HashType> hashes{
      kNumBlocks - block_hashes, hash_stub};

  for (decltype(top_height) i = top_height - block_hashes + 1; i <= top_height;
       ++i) {
    auto block_result = (*block_query)->getBlock(i);

    if (auto e = expected::resultToOptionalError(block_result)) {
      return iroha::expected::makeError(std::move(e->message));
    }

    auto &block =
        boost::get<
            expected::Value<std::unique_ptr<shared_model::interface::Block>>>(
            block_result)
            .value;
    hashes.push_back(block->hash());
  }

  auto factory = std::make_unique<shared_model::proto::ProtoProposalFactory<
      shared_model::validation::DefaultProposalValidator>>(validators_config_);

  const uint64_t kCounter = 0, kMaxLocalCounter = 2;
  // reject_delay and local_counter are local mutable variables of lambda
  const auto kMaxDelay(max_rounds_delay_);
  const auto kMaxDelayIncrement(std::chrono::milliseconds(1000));
  auto delay = [reject_delay = std::chrono::milliseconds(0),
                local_counter = kCounter,
                // MSVC requires const variables to be captured
                kMaxDelay,
                kMaxDelayIncrement,
                kMaxLocalCounter](const auto &commit) mutable {
    using iroha::synchronizer::SynchronizationOutcomeType;
    if (commit.sync_outcome == SynchronizationOutcomeType::kReject
        or commit.sync_outcome == SynchronizationOutcomeType::kNothing) {
      // Increment reject_counter each local_counter calls of function
      ++local_counter;
      if (local_counter == kMaxLocalCounter) {
        local_counter = 0;
        if (reject_delay < kMaxDelay) {
          reject_delay += std::min(kMaxDelay, kMaxDelayIncrement);
        }
      }
    } else {
      reject_delay = std::chrono::milliseconds(0);
    }
    return reject_delay;
  };

  std::shared_ptr<iroha::ordering::ProposalCreationStrategy> proposal_strategy =
      std::make_shared<ordering::KickOutProposalCreationStrategy>(
          getSupermajorityChecker(kConsensusConsistencyModel));

  ordering_gate =
      ordering_init.initOrderingGate(max_proposal_size_,
                                     proposal_delay_,
                                     std::move(hashes),
                                     transaction_factory,
                                     batch_parser,
                                     transaction_batch_factory_,
                                     async_call_,
                                     std::move(factory),
                                     proposal_factory,
                                     persistent_cache,
                                     proposal_strategy,
                                     delay,
                                     log_manager_->getChild("Ordering"));
  log_->info("[Init] => init ordering gate - [{}]",
             logger::boolRepr(bool(ordering_gate)));
  return {};
}

/**
 * Initializing iroha verified proposal creator and block creator
 */
Irohad::RunResult Irohad::initSimulator() {
  return storage->createCommandExecutor() |
             [this](auto &&command_executor) -> RunResult {
    auto block_factory =
        std::make_unique<shared_model::proto::ProtoBlockFactory>(
            //  Block factory in simulator uses UnsignedBlockValidator because
            //  it is not required to check signatures of block here, as they
            //  will be checked when supermajority of peers will sign the block.
            //  It is also not required to validate signatures of transactions
            //  here because they are validated in the ordering gate, where they
            //  are received from the ordering service.
            std::make_unique<
                shared_model::validation::DefaultUnsignedBlockValidator>(
                block_validators_config_),
            std::make_unique<shared_model::validation::ProtoBlockValidator>());

    simulator = std::make_shared<Simulator>(
        std::move(command_executor),
        ordering_gate,
        stateful_validator,
        storage,
        crypto_signer_,
        std::move(block_factory),
        log_manager_->getChild("Simulator")->getLogger());

    log_->info("[Init] => init simulator");
    return {};
  };
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
                                  log_manager_->getChild("BlockLoader"));

  log_->info("[Init] => block loader");
  return {};
}

/**
 * Initializing consensus gate
 */
Irohad::RunResult Irohad::initConsensusGate() {
  auto block_query = storage->createBlockQuery();
  if (not block_query) {
    return iroha::expected::makeError<std::string>(
        "Failed to create block query");
  }
  auto block_var =
      (*block_query)->getBlock((*block_query)->getTopBlockHeight());
  if (auto e = expected::resultToOptionalError(block_var)) {
    return iroha::expected::makeError<std::string>(
        "Failed to get the top block: " + e->message);
  }

  auto &block =
      boost::get<expected::ValueOf<decltype(block_var)>>(&block_var)->value;
  consensus_gate = yac_init->initConsensusGate(
      {block->height(), ordering::kFirstRejectRound},
      storage,
      opt_alternative_peers_,
      simulator,
      block_loader,
      keypair,
      consensus_result_cache_,
      vote_delay_,
      async_call_,
      kConsensusConsistencyModel,
      log_manager_->getChild("Consensus"));
  consensus_gate->onOutcome().subscribe(
      consensus_gate_events_subscription,
      consensus_gate_objects.get_subscriber());
  log_->info("[Init] => consensus gate");
  return {};
}

/**
 * Initializing synchronizer
 */
Irohad::RunResult Irohad::initSynchronizer() {
  return storage->createCommandExecutor() |
             [this](auto &&command_executor) -> RunResult {
    synchronizer = std::make_shared<SynchronizerImpl>(
        std::move(command_executor),
        consensus_gate,
        chain_validator,
        storage,
        storage,
        block_loader,
        log_manager_->getChild("Synchronizer")->getLogger());

    log_->info("[Init] => synchronizer");
    return {};
  };
}

/**
 * Initializing peer communication service
 */
Irohad::RunResult Irohad::initPeerCommunicationService() {
  pcs = std::make_shared<PeerCommunicationServiceImpl>(
      ordering_gate,
      synchronizer,
      simulator,
      log_manager_->getChild("PeerCommunicationService")->getLogger());

  pcs->onProposal().subscribe([this](const auto &) {
    log_->info("~~~~~~~~~| PROPOSAL ^_^ |~~~~~~~~~ ");
  });

  pcs->onSynchronization().subscribe([this](const auto &event) {
    using iroha::synchronizer::SynchronizationOutcomeType;
    switch (event.sync_outcome) {
      case SynchronizationOutcomeType::kCommit:
        log_->info(R"(~~~~~~~~~| COMMIT =^._.^= |~~~~~~~~~ )");
        break;
      case SynchronizationOutcomeType::kReject:
        log_->info(R"(~~~~~~~~~| REJECT \(*.*)/ |~~~~~~~~~ )");
        break;
      case SynchronizationOutcomeType::kNothing:
        log_->info(R"(~~~~~~~~~| EMPTY (-_-)zzz |~~~~~~~~~ )");
        break;
      default:
        break;
    }
  });

  pending_txs_storage_init->setSubscriptions(*pcs);

  log_->info("[Init] => pcs");
  return {};
}

Irohad::RunResult Irohad::initStatusBus() {
  status_bus_ = std::make_shared<StatusBusImpl>();
  log_->info("[Init] => Tx status bus");
  return {};
}

Irohad::RunResult Irohad::initMstProcessor() {
  auto mst_logger_manager =
      log_manager_->getChild("MultiSignatureTransactions");
  auto mst_state_logger = mst_logger_manager->getChild("State")->getLogger();
  auto mst_completer = std::make_shared<DefaultCompleter>(mst_expiration_time_);
  auto mst_storage = std::make_shared<MstStorageStateImpl>(
      mst_completer,
      mst_state_logger,
      mst_logger_manager->getChild("Storage")->getLogger());
  std::shared_ptr<iroha::PropagationStrategy> mst_propagation;
  if (is_mst_supported_) {
    mst_transport = std::make_shared<iroha::network::MstTransportGrpc>(
        async_call_,
        transaction_factory,
        batch_parser,
        transaction_batch_factory_,
        persistent_cache,
        mst_completer,
        keypair.publicKey(),
        std::move(mst_state_logger),
        mst_logger_manager->getChild("Transport")->getLogger());
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

  pending_txs_storage_init->setSubscriptions(*mst_processor);

  log_->info("[Init] => MST processor");
  return {};
}

Irohad::RunResult Irohad::initPendingTxsStorage() {
  pending_txs_storage_ =
      pending_txs_storage_init->createPendingTransactionsStorage();
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
  auto tx_processor = std::make_shared<TransactionProcessorImpl>(
      pcs,
      mst_processor,
      status_bus_,
      status_factory,
      storage->on_commit(),
      command_service_log_manager->getChild("Processor")->getLogger());
  command_service = std::make_shared<::torii::CommandServiceImpl>(
      tx_processor,
      storage,
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
          consensus_gate_objects.get_observable().map([](const auto &) {
            return ::torii::CommandServiceTransportGrpc::ConsensusGateEvent{};
          }),
          stale_stream_max_rounds_,
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
  wsv_restorer_ = std::make_shared<iroha::ametsuchi::WsvRestorerImpl>();
  return {};
}

/**
 * Run iroha daemon
 */
Irohad::RunResult Irohad::run() {
  using iroha::expected::operator|;
  using iroha::operator|;

  // Initializing torii server
  torii_server = std::make_unique<ServerRunner>(
      listen_ip_ + ":" + std::to_string(torii_port_),
      log_manager_->getChild("ToriiServerRunner")->getLogger(),
      false);

  // Initializing internal server
  internal_server = std::make_unique<ServerRunner>(
      listen_ip_ + ":" + std::to_string(internal_port_),
      log_manager_->getChild("InternalServerRunner")->getLogger(),
      false);

  auto make_port_logger = [this](std::string server_name) {
    return [this, server_name](auto port) -> RunResult {
      log_->info("{} server bound on port {}", server_name, port);
      return {};
    };
  };

  // Run torii server
  auto run_result = torii_server->append(command_service_transport)
                        .append(query_service)
                        .run()
      | make_port_logger("Torii");

  // Run torii TLS server
  torii_tls_creds_ | [&, this](const auto &tls_creds) {
    run_result |= [&, this] {
      torii_tls_server = std::make_unique<ServerRunner>(
          listen_ip_ + ":" + std::to_string(torii_tls_params_->port),
          log_manager_->getChild("ToriiTlsServerRunner")->getLogger(),
          false,
          tls_creds);
      return (*torii_tls_server)
                 ->append(command_service_transport)
                 .append(query_service)
                 .run()
          | make_port_logger("Torii TLS");
    };
  };

  // Run internal server
  run_result |= [&, this] {
    if (is_mst_supported_) {
      internal_server->append(
          std::static_pointer_cast<MstTransportGrpc>(mst_transport));
    }
    return internal_server->append(ordering_init.service)
               .append(yac_init->getConsensusNetwork())
               .append(loader_init.service)
               .run()
        | make_port_logger("Internal");
  };

  return run_result | [&]() -> RunResult {
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

    auto initial_ledger_state = std::make_shared<LedgerState>(
        std::move(peers.value()), block->height(), block->hash());

    pcs->onSynchronization().subscribe(
        ordering_init.sync_event_notifier.get_subscriber());
    storage->on_commit().subscribe(
        ordering_init.commit_notifier.get_subscriber());

    ordering_init.commit_notifier.get_subscriber().on_next(std::move(block));

    ordering_init.sync_event_notifier.get_subscriber().on_next(
        synchronizer::SynchronizationEvent{
            SynchronizationOutcomeType::kCommit,
            {block_height, ordering::kFirstRejectRound},
            initial_ledger_state});
    return {};
  };
}
