/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LIBS_COMMON_IROHAD_VERSION_HPP
#define LIBS_COMMON_IROHAD_VERSION_HPP

// disabling GNU macros
#ifdef major
#undef major
#endif

#ifdef minor
#undef minor
#endif

namespace iroha {

  /// A string describing current git repository version in a human-readable way
  extern const char *kGitPrettyVersion;

  struct IrohadVersion {
    unsigned int major;
    unsigned int minor;
    unsigned int patch;

    bool operator==(const IrohadVersion &) const;
  };

  IrohadVersion getIrohadVersion();

}  // namespace iroha

#endif  // LIBS_COMMON_IROHAD_VERSION_HPP
