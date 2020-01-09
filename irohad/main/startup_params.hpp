/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_STARTUP_PARAMS_HPP
#define IROHA_STARTUP_PARAMS_HPP

namespace iroha {
  /// Policy regarging possible existing WSV data at startup
  enum class StartupWsvDataPolicy {
    kReuse,  //!< try to reuse existing data in the
    kDrop,   //!< drop any existing state data
  };
}  // namespace iroha

#endif
