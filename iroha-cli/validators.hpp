/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gflags/gflags.h>
#include <string>

namespace iroha_cli {

  bool validate_port(const char *, gflags::int32);
  bool validate_peers(const char *, const std::string &);
  bool validate_config(const char *, const std::string &);
  bool validate_genesis_block(const char *, const std::string &);

}  // namespace iroha_cli
