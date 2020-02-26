/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common/irohad_version.hpp"

#include <ciso646>

namespace iroha {

  const char *kGitPrettyVersion = GIT_REPO_PRETTY_VER;

  IrohadVersion getIrohadVersion() {
    return IrohadVersion{
        IROHA_MAJOR_VERSION, IROHA_MINOR_VERSION, IROHA_PATCH_VERSION};
  }

  bool IrohadVersion::operator==(const IrohadVersion &rhs) const {
    return major == rhs.major and minor == rhs.minor and patch == rhs.patch;
  }

}  // namespace iroha
