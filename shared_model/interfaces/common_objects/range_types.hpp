/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_RANGE_TYPES_HPP
#define IROHA_SHARED_MODEL_RANGE_TYPES_HPP

#include <boost/range/any_range.hpp>
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    class Signature;
    class Transaction;
    class AccountAsset;

    namespace types {

      using ByteRange = boost::iterator_range<ByteType *>;
      using ConstByteRange = boost::iterator_range<const ByteType *>;
      /// Type of signature range, which returns when signatures are invoked
      using SignatureRangeType = boost::any_range<interface::Signature,
                                                  boost::forward_traversal_tag,
                                                  const Signature &>;
      /// Type of transactions' collection
      using TransactionsCollectionType =
          boost::any_range<Transaction,
                           boost::random_access_traversal_tag,
                           const Transaction &>;
      using AccountAssetCollectionType =
          boost::any_range<AccountAsset,
                           boost::random_access_traversal_tag,
                           const AccountAsset &>;
      /// Type of hash collection
      using HashCollectionType = boost::
          any_range<HashType, boost::forward_traversal_tag, const HashType &>;

    }  // namespace types
  }    // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_RANGE_TYPES_HPP
