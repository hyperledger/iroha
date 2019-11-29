/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <csignal>
#include <fstream>
#include <thread>

#include <gflags/gflags.h>
#include <grpc++/grpc++.h>
#include "ametsuchi/storage.hpp"
#include "backend/protobuf/common_objects/proto_common_objects_factory.hpp"
#include "common/bind.hpp"
#include "common/files.hpp"
#include "common/irohad_version.hpp"
#include "common/result.hpp"
#include "crypto/keys_manager_impl.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/application.hpp"
#include "main/impl/pg_connection_init.hpp"
#include "main/iroha_conf_literals.hpp"
#include "main/iroha_conf_loader.hpp"
#include "main/raw_block_loader.hpp"
#include "validators/field_validator.hpp"

static const std::string kListenIp = "0.0.0.0";
static const std::string kLogSettingsFromConfigFile = "config_file";
static const uint32_t kMstExpirationTimeDefault = 1440;
static const uint32_t kMaxRoundsDelayDefault = 3000;
static const uint32_t kStaleStreamMaxRoundsDefault = 2;
static const std::string kDefaultWorkingDatabaseName{"iroha_default"};

/**
 * Gflag validator.
 * Validator for the configuration file path input argument.
 * Path is considered to be valid if it is not empty.
 * @param flag_name - flag name. Must be 'config' in this case
 * @param path      - file name. Should be path to the config file
 * @return true if argument is valid
 */
bool validate_config(const char *flag_name, std::string const &path) {
  return not path.empty();
}

/**
 * Gflag validator.
 * Validator for the keypair files path input argument.
 * Path is considered to be valid if it is not empty.
 * @param flag_name - flag name. Must be 'keypair_name' in this case
 * @param path      - file name. Should be path to the keypair files
 * @return true if argument is valid
 */
bool validate_keypair_name(const char *flag_name, std::string const &path) {
  return not path.empty();
}

/**
 * Creating input argument for the configuration file location.
 */
DEFINE_string(config, "", "Specify iroha provisioning path.");
/**
 * Registering validator for the configuration file location.
 */
DEFINE_validator(config, &validate_config);

/**
 * Creating input argument for the genesis block file location.
 */
DEFINE_string(genesis_block, "", "Specify file with initial block");

/**
 * Creating input argument for the keypair files location.
 */
DEFINE_string(keypair_name, "", "Specify name of .pub and .priv files");
/**
 * Registering validator for the keypair files location.
 */
DEFINE_validator(keypair_name, &validate_keypair_name);

/**
 * Creating boolean flag for overwriting already existing block storage
 */
DEFINE_bool(overwrite_ledger, false, "Overwrite ledger data if existing");

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

std::promise<void> exit_requested;

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
  gflags::SetVersionString(iroha::kGitPrettyVersion);

  // Parsing command line arguments
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  logger::LoggerManagerTreePtr log_manager;
  logger::LoggerPtr log;

  // If the global log level override was set in the command line arguments,
  // create a logger manager with the given log level for all subsystems:
  if (FLAGS_verbosity != kLogSettingsFromConfigFile) {
    logger::LoggerConfig cfg;
    cfg.log_level = config_members::LogLevels.at(FLAGS_verbosity);
    log_manager = std::make_shared<logger::LoggerManagerTree>(std::move(cfg));
    log = log_manager->getChild("Init")->getLogger();
  }

  // Check if validators are registered.
  if (not config_validator_registered
      or not keypair_name_validator_registered) {
    // Abort execution if not
    if (log) {
      log->error("Flag validator is not registered");
    }
    return EXIT_FAILURE;
  }

  // Reading iroha configuration file
  auto config_result =
      parse_iroha_config(FLAGS_config, getCommonObjectsFactory());
  if (auto e = iroha::expected::resultToOptionalError(config_result)) {
    log->error("Failed reading the configuration file: {}", e.value());
    return EXIT_FAILURE;
  }
  auto config = iroha::expected::resultToValue(std::move(config_result));

  if (not log_manager) {
    log_manager = config.logger_manager.value_or(getDefaultLogManager());
    log = log_manager->getChild("Init")->getLogger();
  }
  log->info("Irohad version: {}", iroha::kGitPrettyVersion);
  log->info("config initialized");

  if (config.initial_peers and config.initial_peers->empty()) {
    log->critical(
        "Got an empty initial peers list in configuration file. You have to "
        "either specify some peers or avoid overriding the peers from genesis "
        "block!");
    return EXIT_FAILURE;
  }

  // Reading public and private key files
  iroha::KeysManagerImpl keysManager(
      FLAGS_keypair_name, log_manager->getChild("KeysManager")->getLogger());
  auto keypair = keysManager.loadKeys(boost::none);
  // Check if both keys are read properly
  if (auto e = iroha::expected::resultToOptionalError(keypair)) {
    // Abort execution if not
    log->error("Failed to load keypair: {}", e.value());
    return EXIT_FAILURE;
  }

  std::unique_ptr<iroha::ametsuchi::PostgresOptions> pg_opt;
  if (config.database_config) {
    pg_opt = std::make_unique<iroha::ametsuchi::PostgresOptions>(
        config.database_config->host,
        config.database_config->port,
        config.database_config->user,
        config.database_config->password,
        config.database_config->working_dbname,
        config.database_config->maintenance_dbname,
        log);
  } else if (config.pg_opt) {
    log->warn("Using deprecated database connection string!");
    pg_opt = std::make_unique<iroha::ametsuchi::PostgresOptions>(
        config.pg_opt.value(), kDefaultWorkingDatabaseName, log);
  } else {
    log->critical("Missing database configuration!");
    return EXIT_FAILURE;
  }

  // Configuring iroha daemon
  Irohad irohad(
      config.block_store_path,
      std::move(pg_opt),
      kListenIp,  // TODO(mboldyrev) 17/10/2018: add a parameter in
                  // config file and/or command-line arguments?
      config.torii_port,
      config.internal_port,
      config.max_proposal_size,
      std::chrono::milliseconds(config.proposal_delay),
      std::chrono::milliseconds(config.vote_delay),
      std::chrono::minutes(
          config.mst_expiration_time.value_or(kMstExpirationTimeDefault)),
      iroha::expected::resultToValue(std::move(keypair)),
      std::chrono::milliseconds(
          config.max_round_delay_ms.value_or(kMaxRoundsDelayDefault)),
      config.stale_stream_max_rounds.value_or(kStaleStreamMaxRoundsDefault),
      std::move(config.initial_peers),
      log_manager->getChild("Irohad"),
      boost::make_optional(config.mst_support,
                           iroha::GossipPropagationStrategyParams{}),
      config.torii_tls_params);

  // Check if iroha daemon storage was successfully initialized
  if (not irohad.storage) {
    // Abort execution if not
    log->error("Failed to initialize storage");
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
  bool blockstore = irohad.storage->getBlockQuery()->getTopBlockHeight() != 0;

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
      auto block = iroha::expected::resultToValue(std::move(block_result));

      if (not blockstore and overwrite) {
        log->warn(
            "Blockstore is empty - there is nothing to overwrite. Inserting "
            "new genesis block.");
      }

      // clear previous storage if any
      irohad.dropStorage();

      const auto txs_num = block->transactions().size();
      if (not irohad.storage->insertBlock(std::move(block))) {
        log->critical("Could not apply genesis block!");
        return EXIT_FAILURE;
      }
      log->info("Genesis block inserted, number of transactions: {}", txs_num);
    }
  } else {  // genesis block file is not specified
    if (not blockstore) {
      log->error(
          "Cannot restore nor create new state. Blockstore is empty. No "
          "genesis block is provided. Please pecify new genesis block using "
          "--genesis_block parameter.");
      return EXIT_FAILURE;
    } else {
      if (overwrite) {
        log->warn(
            "No new genesis block is specified - blockstore cannot be "
            "overwritten. If you want overwrite ledger state, please "
            "specify new genesis block using --genesis_block parameter.");
      }
    }
  }

  // check if at least one block is available in the ledger
  auto block_query = irohad.storage->getBlockQuery();
  if (not block_query) {
    log->error("Cannot create BlockQuery");
    return EXIT_FAILURE;
  }
  const bool blocks_exist{iroha::expected::hasValue(
      block_query->getBlock(block_query->getTopBlockHeight()))};
  block_query.reset();

  if (not blocks_exist) {
    log->error(
        "Unable to start the ledger. There are no blocks in the ledger. Please "
        "ensure that you are not trying to start the newer version of "
        "the ledger over incompatible version of the storage or there is "
        "enough disk space. Try to specify --genesis_block and "
        "--overwrite_ledger parameters at the same time.");
    return EXIT_FAILURE;
  }

  // init pipeline components
  auto init_result = irohad.init();
  if (auto error =
          boost::get<iroha::expected::Error<std::string>>(&init_result)) {
    log->critical("Irohad startup failed: {}", error->error);
    return EXIT_FAILURE;
  }

  auto handler = [](int s) { exit_requested.set_value(); };
  std::signal(SIGINT, handler);
  std::signal(SIGTERM, handler);
#ifdef SIGQUIT
  std::signal(SIGQUIT, handler);
#endif

  // runs iroha
  log->info("Running iroha");
  auto run_result = irohad.run();
  if (auto error =
          boost::get<iroha::expected::Error<std::string>>(&run_result)) {
    log->critical("Irohad startup failed: {}", error->error);
    return EXIT_FAILURE;
  }
  exit_requested.get_future().wait();

  // We do not care about shutting down grpc servers
  // They do all necessary work in their destructors
  log->info("shutting down...");

  gflags::ShutDownCommandLineFlags();

  return 0;
}
