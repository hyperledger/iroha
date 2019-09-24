/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_SETTING_QUERY_HPP
#define IROHA_MOCK_SETTING_QUERY_HPP

#include "ametsuchi/setting_query.hpp"

#include <gmock/gmock.h>
#include <boost/optional.hpp>

namespace iroha {
  namespace ametsuchi {
    class MockSettingQuery : public SettingQuery {
     public:
      MOCK_METHOD1(getSettingValue,
                   boost::optional<SettingValueType>(const SettingKeyType &));
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_SETTING_QUERY_HPP
