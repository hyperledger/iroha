/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SETTING_QUERY_FACTORY_HPP
#define IROHA_SETTING_QUERY_FACTORY_HPP

#include <boost/optional.hpp>

#include "ametsuchi/setting_query.hpp"

namespace iroha {
  namespace ametsuchi {
    class SettingQueryFactory {
     public:
      /**
       * Creates a setting query
       * @return Created setting query
       */
      virtual boost::optional<std::unique_ptr<SettingQuery>>
      createSettingQuery() const = 0;

      virtual ~SettingQueryFactory() = default;
    };
  }  // namespace ametsuchi
}  // namespace iroha
#endif  // IROHA_SETTING_QUERY_FACTORY_HPP
