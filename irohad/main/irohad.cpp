/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gflags/gflags.h>
#include <grpc++/grpc++.h>

#include <chrono>
#include <csignal>
#include <fstream>
#include <future>
#include <thread>

#include "ametsuchi/storage.hpp"
#include "backend/protobuf/common_objects/proto_common_objects_factory.hpp"
#include "common/bind.hpp"
#include "common/files.hpp"
#include "common/hexutils.hpp"
#include "common/irohad_version.hpp"
#include "common/result.hpp"
#include "crypto/keys_manager_impl.hpp"
#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"
#include "cryptography/private_key.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/application.hpp"
#include "main/impl/pg_connection_init.hpp"
#include "main/impl/rocksdb_connection_init.hpp"
#include "main/iroha_conf_literals.hpp"
#include "main/iroha_conf_loader.hpp"
#include "main/raw_block_loader.hpp"
#include "maintenance/metrics.hpp"
#include "network/impl/channel_factory.hpp"
#include "util/status_notifier.hpp"
#include "util/utility_service.hpp"
#include "validators/field_validator.hpp"

#if defined(USE_LIBURSA)
#include "cryptography/ed25519_ursa_impl/crypto_provider.hpp"
#define ED25519_PROVIDER shared_model::crypto::CryptoProviderEd25519Ursa
#endif

static const std::string kListenIp = "0.0.0.0";
static const std::string kLogSettingsFromConfigFile = "config_file";
static const std::string kDefaultWorkingDatabaseName{"iroha_default"};
static const std::chrono::milliseconds kExitCheckPeriod{1000};

/**
 * Creating input argument for the configuration file location.
 */
DEFINE_string(config, "", "Specify iroha provisioning path.");

/**
 * Creating input argument for the genesis block file location.
 */
DEFINE_string(genesis_block, "", "Specify file with initial block");

/**
 * Creating input argument for the keypair files location.
 */
DEFINE_string(keypair_name, "", "Specify name of .pub and .priv files");

/**
 * Creating boolean flag for overwriting already existing block storage
 */
DEFINE_bool(overwrite_ledger, false, "Overwrite ledger data if existing");

/**
 * Startup option to reuse existing WSV. Ignored since state is reused by
 * default.
 */
DEFINE_bool(reuse_state,
            true,
            "Try to reuse existing state data at startup (Deprecated, startup "
            "reuses state by default. Use drop_state to drop the WSV).");

/**
 * Startup option to drop existing WSV. Cannot be used with 'reuse_state'.
 */
DEFINE_bool(drop_state, false, "Drops existing state data at startup.");

/**
 * Startup option for WSV synchronization mode.
 */
DEFINE_bool(wait_for_new_blocks,
            false,
            "Startup synchronization policy - waits for new blocks in "
            "blockstore, does not run network");

static bool validateVerbosity(const char *flagname, const std::string &val) {
  if (val == kLogSettingsFromConfigFile) {
    return true;
  }
  const auto it = config_members::LogLevels.find(val);
  if (it == config_members::LogLevels.end()) {
    std::cerr << "Invalid value for " << flagname << ": should be one of '"
              << kLogSettingsFromConfigFile;
    for (const auto &level : config_members::LogLevels) {
      std::cerr << "', '" << level.first;
    }
    std::cerr << "'." << std::endl;
    return false;
  }
  return true;
}

/// Verbosity flag for spdlog configuration
DEFINE_string(verbosity, kLogSettingsFromConfigFile, "Log verbosity");
DEFINE_validator(verbosity, &validateVerbosity);

/// Metrics. ToDo validator
DEFINE_string(metrics_addr,
              "127.0.0.1",
              "Prometeus HTTP server listen address");
DEFINE_string(metrics_port,
              "",
              "Prometeus HTTP server listens port, disabled by default");

DEFINE_bool(exit_after_init, false, "Use this flag to reindex WSV and exit");

DEFINE_bool(syncing_node, false, "Use this flag to run iroha as syncing node");

std::sig_atomic_t caught_signal = 0;
std::promise<void> exit_requested;

std::shared_ptr<iroha::utility_service::UtilityService> utility_service;
std::unique_ptr<iroha::network::ServerRunner> utility_server;
std::mutex shutdown_wait_mutex;
std::lock_guard<std::mutex> shutdown_wait_locker(shutdown_wait_mutex);
std::shared_ptr<iroha::utility_service::StatusNotifier> daemon_status_notifier =
    std::make_shared<iroha::utility_service::StatusNotifier>();

static shared_model::crypto::Keypair getKeypairFromConfig(
    IrohadConfig::Crypto const &config) {
  auto const provider_it = config.providers.find(config.signer);
  if (provider_it == config.providers.end()) {
    throw std::runtime_error{
        fmt::format("crypto provider `{}' is not specified", config.signer)};
  }
  auto const &signer = provider_it->second;

  shared_model::crypto::PrivateKey private_key{
      iroha::hexstringToBytestringResult(signer.private_key.value())
          .assumeValue()};

  switch (signer.type) {
    case iroha::multihash::Type::ed25519_sha3_256:
      return shared_model::crypto::CryptoProviderEd25519Sha3::generateKeypair(
          private_key);
#if defined(USE_LIBURSA)
    case iroha::multihash::Type::ed25519pub:
      return ED25519_PROVIDER::generateKeypair(private_key);
#endif
    default:
      daemon_status_notifier->notify(::iroha::utility_service::Status::kFailed);
      throw std::runtime_error{"unsupported crypto algorithm"};
  }
}

static shared_model::crypto::Keypair getKeypairFromFile(
    std::string const &keypair_name, logger::LoggerManagerTreePtr log_manager) {
  iroha::KeysManagerImpl keys_manager{
      keypair_name, log_manager->getChild("KeysManager")->getLogger()};

  using shared_model::crypto::Keypair;
  return keys_manager.loadKeys(boost::none)
      .match([](auto &&keypair_val) { return std::move(keypair_val).value; },
             [&](auto const &e) -> Keypair {
               daemon_status_notifier->notify(
                   ::iroha::utility_service::Status::kFailed);
               throw std::runtime_error{
                   fmt::format("Failed to load keypair: {}", e.error)};
             });
}

void initUtilityService(
    const IrohadConfig::UtilityService &config,
    iroha::utility_service::UtilityService::ShutdownCallback shutdown_callback,
    logger::LoggerManagerTreePtr log_manager) {
  auto utility_service =
      std::make_shared<iroha::utility_service::UtilityService>(
          shutdown_callback,
          log_manager->getChild("UtilityService")->getLogger());
  utility_server = std::make_unique<iroha::network::ServerRunner>(
      config.ip + ":" + std::to_string(config.port),
      log_manager->getChild("UtilityServer")->getLogger(),
      false);
  utility_server->append(utility_service)
      .run()
      .match(
          [&](const auto &port) {
            assert(port.value == config.port);
            log_manager->getLogger()->info("Utility server bound on port {}",
                                           port.value);
          },
          [](const auto &e) { throw std::runtime_error(e.error); });
  daemon_status_notifier = utility_service;
}

logger::LoggerManagerTreePtr getDefaultLogManager() {
  return std::make_shared<logger::LoggerManagerTree>(logger::LoggerConfig{
      logger::LogLevel::kInfo, logger::getDefaultLogPatterns()});
}

std::shared_ptr<shared_model::interface::CommonObjectsFactory>
getCommonObjectsFactory() {
  auto validators_config =
      std::make_shared<shared_model::validation::ValidatorsConfig>(0);
  return std::make_shared<shared_model::proto::ProtoCommonObjectsFactory<
      shared_model::validation::FieldValidator>>(validators_config);
}

int main(int argc, char *argv[]) {
  auto version = std::string(iroha::kGitPrettyVersion);
#if defined(USE_BURROW)
  version += " burrow";
#endif
#if defined(USE_LIBURSA)
  version += " ursa";
#endif
  gflags::SetVersionString(version);

  // Parsing command line arguments
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  logger::LoggerManagerTreePtr log_manager = getDefaultLogManager();
  logger::LoggerPtr log = log_manager->getChild("Init")->getLogger();

  try {
    // If the global log level override was set in the command line arguments,
    // create a logger manager with the given log level for all subsystems:
    if (FLAGS_verbosity != kLogSettingsFromConfigFile) {
      logger::LoggerConfig cfg;
      cfg.log_level = config_members::LogLevels.at(FLAGS_verbosity);
      log_manager = std::make_shared<logger::LoggerManagerTree>(std::move(cfg));
      log = log_manager->getChild("Init")->getLogger();
    }

    auto config_result =
        parse_iroha_config(FLAGS_config, getCommonObjectsFactory(), {log});
    if (auto e = iroha::expected::resultToOptionalError(config_result)) {
      if (log) {
        log->error("Failed reading the configuration: {}", e.value());
      }
      return EXIT_FAILURE;
    }
    auto config = std::move(config_result).assumeValue();
    config.syncing_mode = FLAGS_syncing_node;

    if (FLAGS_verbosity == kLogSettingsFromConfigFile) {
      log_manager = config.logger_manager.value_or(getDefaultLogManager());
      log = log_manager->getChild("Init")->getLogger();
    }
    log->info("Irohad version: {}", iroha::kGitPrettyVersion);
    log->info("config initialized");

    if (config.initial_peers and config.initial_peers->empty()) {
      log->critical(
          "Got an empty initial peers list in configuration file. You have to "
          "either specify some peers or avoid overriding the peers from "
          "genesis block!");
      return EXIT_FAILURE;
    }

    if (config.utility_service) {
      initUtilityService(config.utility_service.value(),
                         [] {
                           exit_requested.set_value();
                           std::lock_guard<std::mutex>{shutdown_wait_mutex};
                         },
                         log_manager);
    }

    daemon_status_notifier->notify(
        ::iroha::utility_service::Status::kInitialization);

    boost::optional<shared_model::crypto::Keypair> keypair = boost::none;
    if (!FLAGS_keypair_name.empty()) {
      keypair = getKeypairFromFile(FLAGS_keypair_name, log_manager);
    } else if (config.crypto.has_value()) {
      keypair = getKeypairFromConfig(config.crypto.value());
    }

    std::unique_ptr<iroha::ametsuchi::PostgresOptions> pg_opt;
    std::unique_ptr<iroha::ametsuchi::RocksDbOptions> rdb_opt;
    if (config.database_config) {
      if (config.database_config->type == kDbTypeRocksdb)
        rdb_opt = std::make_unique<iroha::ametsuchi::RocksDbOptions>(
            config.database_config->path);
      else if (config.database_config->type == kDbTypePostgres)
        pg_opt = std::make_unique<iroha::ametsuchi::PostgresOptions>(
            config.database_config->host,
            config.database_config->port,
            config.database_config->user,
            config.database_config->password,
            config.database_config->working_dbname,
            config.database_config->maintenance_dbname,
            log);
      else {
        log->critical("Unsupported database type!");
        daemon_status_notifier->notify(
            ::iroha::utility_service::Status::kFailed);
        return EXIT_FAILURE;
      }
    } else if (config.pg_opt) {
      log->warn("Using deprecated database connection string!");
      pg_opt = std::make_unique<iroha::ametsuchi::PostgresOptions>(
          config.pg_opt.value(), kDefaultWorkingDatabaseName, log);
    } else {
      log->critical("Missing database configuration!");
      daemon_status_notifier->notify(::iroha::utility_service::Status::kFailed);
      return EXIT_FAILURE;
    }

    // Configuring iroha daemon
    auto irohad = std::make_unique<Irohad>(
        config,
        std::move(pg_opt),
        std::move(rdb_opt),
        kListenIp,  // TODO(mboldyrev) 17/10/2018: add a parameter in
                    // config file and/or command-line arguments?
        std::move(keypair),
        log_manager->getChild("Irohad"),
        FLAGS_drop_state ? iroha::StartupWsvDataPolicy::kDrop
                         : iroha::StartupWsvDataPolicy::kReuse,
        FLAGS_wait_for_new_blocks
            ? iroha::StartupWsvSynchronizationPolicy::kWaitForNewBlocks
            : iroha::StartupWsvSynchronizationPolicy::kSyncUpAndGo,
        std::nullopt,
        boost::none);

    // Check if iroha daemon storage was successfully initialized
    if (not irohad->storage) {
      // Abort execution if not
      log->error("Failed to initialize storage");
      daemon_status_notifier->notify(::iroha::utility_service::Status::kFailed);
      return EXIT_FAILURE;
    }

    /*
     * The logic implemented below is reflected in the following truth table.
     *
    +------------+--------------+------------------+---------------+---------+
    | Blockstore | New genesis  | Overwrite ledger | Genesis block | Message |
    | presence   | block is set | flag is set      | that is used  |         |
    +------------+--------------+------------------+---------------+---------+
    | 0          | 1            | 0                | new           |         |
    | 0          | 1            | 1                | new           | warning |
    | 1          | 1            | 0                | old           | warning |
    | 1          | 1            | 1                | new           |         |
    | 0          | 0            | 0                | none          | error   |
    | 0          | 0            | 1                | none          | error   |
    | 1          | 0            | 0                | old           |         |
    | 1          | 0            | 1                | old           | warning |
    +------------+--------------+------------------+---------------+---------+
     */

    /// if there are any blocks in blockstore, then true
    bool blockstore =
        irohad->storage->getBlockQuery()->getTopBlockHeight() != 0;

    /// genesis block file is specified as launch parameter
    bool genesis = not FLAGS_genesis_block.empty();

    /// overwrite ledger flag was set as launch parameter
    bool overwrite = FLAGS_overwrite_ledger;

    if (genesis) {  // genesis block file is specified
      if (blockstore and not overwrite) {
        log->warn(
            "Passed genesis block will be ignored without --overwrite_ledger "
            "flag. Restoring existing state.");
      } else {
        auto block_result =
            iroha::readTextFile(FLAGS_genesis_block) | [](const auto &json) {
              return iroha::main::BlockLoader::parseBlock(json);
            };

        if (auto e = iroha::expected::resultToOptionalError(block_result)) {
          log->error("Failed to parse genesis block: {}", e.value());
          return EXIT_FAILURE;
        }
        auto block = std::move(block_result).assumeValue();

        if (not blockstore and overwrite) {
          log->warn(
              "Blockstore is empty - there is nothing to overwrite. Inserting "
              "new genesis block.");
        }

        // clear previous storage if any
        irohad->dropStorage();
        // Check if iroha daemon storage was successfully re-initialized
        if (not irohad->storage) {
          // Abort execution if not
          log->error("Failed to re-initialize storage");
          daemon_status_notifier->notify(
              ::iroha::utility_service::Status::kFailed);
          return EXIT_FAILURE;
        }

        const auto txs_num = block->transactions().size();
        auto inserted = irohad->storage->insertBlock(std::move(block));
        if (auto e = iroha::expected::resultToOptionalError(inserted)) {
          log->critical("Could not apply genesis block: {}", e.value());
          return EXIT_FAILURE;
        }
        log->info("Genesis block inserted, number of transactions: {}",
                  txs_num);
      }
    } else {  // genesis block file is not specified
      if (not blockstore) {
        log->error(
            "Cannot restore nor create new state. Blockstore is empty. No "
            "genesis block is provided. Please pecify new genesis block using "
            "--genesis_block parameter.");
        return EXIT_FAILURE;
      } else if (overwrite) {
        // no genesis, blockstore present, overwrite specified -> new block
        // store, world state should be reset
        irohad->resetWsv();
        if (not FLAGS_reuse_state) {
          log->warn(
              "No new genesis block is specified - blockstore will not be "
              "overwritten. If you want overwrite ledger state, please "
              "specify new genesis block using --genesis_block parameter. "
              "If you want to reuse existing state data (WSV), consider the "
              "--reuse_state flag.");
        }
      }
    }

    // check if at least one block is available in the ledger
    auto block_query = irohad->storage->getBlockQuery();
    if (not block_query) {
      log->error("Cannot create BlockQuery");
      daemon_status_notifier->notify(::iroha::utility_service::Status::kFailed);
      return EXIT_FAILURE;
    }
    const bool blocks_exist{iroha::expected::hasValue(
        block_query->getBlock(block_query->getTopBlockHeight()))};
    block_query.reset();

    if (not blocks_exist) {
      log->error(
          "Unable to start the ledger. There are no blocks in the ledger. "
          "Please "
          "ensure that you are not trying to start the newer version of "
          "the ledger over incompatible version of the storage or there is "
          "enough disk space. Try to specify --genesis_block and "
          "--overwrite_ledger parameters at the same time.");
      return EXIT_FAILURE;
    }

    // init pipeline components
    auto init_result = irohad->init();
    if (auto error =
            boost::get<iroha::expected::Error<std::string>>(&init_result)) {
      log->critical("Irohad startup failed: {}", error->error);
      daemon_status_notifier->notify(::iroha::utility_service::Status::kFailed);
      return EXIT_FAILURE;
    }

    if (FLAGS_exit_after_init) {
      return EXIT_SUCCESS;
    }

    auto handler = [](int s) { caught_signal = s; };
    std::signal(SIGINT, handler);
    std::signal(SIGTERM, handler);
#ifdef SIGQUIT
    std::signal(SIGQUIT, handler);
#endif

    // start metrics
    std::shared_ptr<Metrics> metrics;  // Must be a pointer because 'this' is
                                       // captured to lambdas in constructor.
    std::string metrics_addr;
    if (FLAGS_metrics_port.size()) {
      metrics_addr = FLAGS_metrics_addr + ":" + FLAGS_metrics_port;
    } else if (config.metrics_addr_port.size()) {
      metrics_addr = config.metrics_addr_port;
    }
    if (metrics_addr.empty()) {
      log->info("Skiping Metrics initialization.");
    } else {
      try {
        metrics =
            Metrics::create(metrics_addr,
                            irohad->storage,
                            log_manager->getChild("Metrics")->getLogger());
        log->info("Metrics listens on {}", metrics->getListenAddress());
      } catch (std::exception const &ex) {
        log->warn("Failed to initialize Metrics: {}", ex.what());
      }
    }

    // runs iroha
    log->info("Running iroha");
    auto run_result = irohad->run();
    if (auto error =
            boost::get<iroha::expected::Error<std::string>>(&run_result)) {
      log->critical("Irohad startup failed: {}", error->error);
      daemon_status_notifier->notify(::iroha::utility_service::Status::kFailed);
      return EXIT_FAILURE;
    }
    daemon_status_notifier->notify(::iroha::utility_service::Status::kRunning);

    auto exit_future = exit_requested.get_future();
    while (exit_future.wait_for(kExitCheckPeriod)
           != std::future_status::ready) {
      if (caught_signal != 0) {
        log->warn("Caught signal {}, exiting.", caught_signal);
        break;
      }
    }
    irohad->printDbStatus();
    daemon_status_notifier->notify(
        ::iroha::utility_service::Status::kTermination);

    // We do not care about shutting down grpc servers
    // They do all necessary work in their destructors
    log->info("shutting down...");

    irohad.reset();
    daemon_status_notifier->notify(::iroha::utility_service::Status::kStopped);

    gflags::ShutDownCommandLineFlags();

    return 0;
  } catch (std::exception const &e) {
    daemon_status_notifier->notify(::iroha::utility_service::Status::kFailed);
    if (log) {
      log->critical("unhandled exception: {}", e.what());
    }
    return EXIT_FAILURE;
  }
}
