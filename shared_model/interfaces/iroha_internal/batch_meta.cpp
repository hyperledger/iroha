/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/iroha_internal/batch_meta.hpp"

#include <boost/range/algorithm/equal.hpp>
#include "cryptography/hash.hpp"

using namespace shared_model::interface;

std::string BatchMeta::toString() const {
  return detail::PrettyStringBuilder()
      .init("BatchMeta")
      .appendNamed("Type",
                   type() == types::BatchType::ATOMIC ? "ATOMIC" : "ORDERED")
      .append(reducedHashes())
      .finalize();
}

bool BatchMeta::operator==(const ModelType &rhs) const {
  return boost::equal(reducedHashes(), rhs.reducedHashes())
      and type() == rhs.type();
}
