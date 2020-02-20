/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_ACCOUNT_HPP
#define IROHA_SHARED_MODEL_ACCOUNT_HPP

#include "cryptography/hash.hpp"
#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    /**
     * User identity information in the system
     */
    class Account : public ModelPrimitive<Account> {
     public:
      /**
       * @return Identity of user, for fetching data
       */
      virtual const types::AccountIdType &accountId() const = 0;

      /**
       * @return Identity of domain, for fetching data
       */
      virtual const types::DomainIdType &domainId() const = 0;

      /**
       * @return Minimum quorum of signatures needed for transactions
       */
      virtual types::QuorumType quorum() const = 0;

      /**
       * @return JSON data stored in account
       */
      virtual const types::JsonType &jsonData() const = 0;

      /**
       * Stringify the data.
       * @return the content of account asset.
       */
      std::string toString() const override {
        return detail::PrettyStringBuilder()
            .init("Account")
            .appendNamed("accountId", accountId())
            .appendNamed("domainId", domainId())
            .appendNamed("quorum", quorum())
            .appendNamed("json", jsonData())
            .finalize();
      }

      /**
       * Checks equality of objects inside
       * @param rhs - other wrapped value
       * @return true, if wrapped objects are same
       */
      bool operator==(const Account &rhs) const override {
        return accountId() == rhs.accountId() and domainId() == rhs.domainId()
            and quorum() == rhs.quorum() and jsonData() == rhs.jsonData();
      }
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_ACCOUNT_HPP
