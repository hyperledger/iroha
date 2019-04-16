/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ADDACCOUNTDETAIL_HPP
#define IROHA_ADDACCOUNTDETAIL_HPP

#include <string>
#include "model/command.hpp"

namespace iroha {
  namespace model {

    struct SetAccountDetail : public Command {
      std::string account_id;
      std::string key;
      std::string value;

      bool operator==(const Command &command) const override;

      SetAccountDetail() {}

      SetAccountDetail(const std::string &account_id,
                       const std::string &key,
                       const std::string &value)
          : account_id(account_id), key(key), value(value) {}
    };

  }  // namespace model
}  // namespace iroha

#endif  // IROHA_ADDACCOUNTDETAIL_HPP
