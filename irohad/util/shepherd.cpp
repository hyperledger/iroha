/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <iostream>

#include "util/proto_status_tools.hpp"

#include <gflags/gflags.h>
#include "common/irohad_version.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/iroha_conf_literals.hpp"
#include "util/utility_client.hpp"

static bool validateVerbosity(const char *flagname, const std::string &val) {
  const auto it = config_members::LogLevels.find(val);
  if (it == config_members::LogLevels.end()) {
    std::cerr << "Invalid value for " << flagname << ": should be one of ";
    for (const auto &level : config_members::LogLevels) {
      std::cerr << " '" << level.first << "'";
    }
    std::cerr << "." << std::endl;
    return false;
  }
  return true;
}

static bool validateSingleAction(const char * /*flagname*/, bool val) {
  static bool got_a_command = false;
  if (got_a_command && val) {
    std::cerr << "More than one command specified!";
    return false;
  }
  got_a_command |= val;
  return true;
}

DEFINE_string(irohad, "127.0.0.1:11001", "Address of iroha daemon");

DEFINE_string(verbosity, "warning", "Log verbosity");
DEFINE_validator(verbosity, &validateVerbosity);

DEFINE_bool(shutdown, false, "Ask the daemon to shut down gracefully");
DEFINE_validator(shutdown, &validateSingleAction);

DEFINE_bool(status, false, "Watch daemon statuses.");
DEFINE_validator(status, &validateSingleAction);

bool printStatus(const iroha::utility_service::Status &status) {
  ::fmt::print("{}", status);
  return true;
}

int main(int argc, char **argv) {
  gflags::SetVersionString(iroha::kGitPrettyVersion);

  // Parsing command line arguments
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  logger::LoggerConfig cfg;
  cfg.log_level = config_members::LogLevels.at(FLAGS_verbosity);
  logger::LoggerManagerTreePtr log_manager =
      std::make_shared<logger::LoggerManagerTree>(std::move(cfg))
          ->getChild("Shepherd");
  logger::LoggerPtr log = log_manager->getLogger();

  iroha::utility_service::UtilityClient client(
      FLAGS_irohad, log_manager->getChild("UtilityClient")->getLogger());

  if (FLAGS_status) {
    return client.status(printStatus) ? EXIT_SUCCESS : EXIT_FAILURE;
  }

  if (FLAGS_shutdown) {
    return client.shutdown() ? EXIT_SUCCESS : EXIT_FAILURE;
  }

  log->error("No command specified!");
  ::gflags::ShowUsageWithFlags(argv[0]);
  return EXIT_FAILURE;
}
