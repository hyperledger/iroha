/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SETTING_QUERY_HPP
#define IROHA_SETTING_QUERY_HPP

#include <boost/optional.hpp>
#include "common/result.hpp"
#include "validators/settings.hpp"

namespace iroha {

  namespace ametsuchi {
    /**
     * Public interface for get settings structure
     */
    class SettingQuery {
     public:
      virtual ~SettingQuery() = default;

      virtual expected::Result<
          std::unique_ptr<const shared_model::validation::Settings>,
          std::string>
      get() = 0;
    };

    extern const shared_model::interface::types::SettingKeyType
        kMaxDescriptionSizeKey;
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_SETTING_QUERY_HPP
