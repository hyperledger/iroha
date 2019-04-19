/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/reconnection/impl/k_times_reconnection_strategy.hpp"

using namespace iroha::ametsuchi;

KTimesReconnectionStorageStrategy::KTimesReconnectionStorageStrategy(
    size_t number_of_recalls)
    : number_of_recalls_(number_of_recalls) {}

bool KTimesReconnectionStorageStrategy::canInvoke(const Tag &tag) {
  CollectionType::accessor accessor;
  while (true) {
    bool is_found = invokes_.find(accessor, tag);
    if (is_found) {
      // assume the tag is unique and doesn't share between threads
      accessor->second++;
    } else {
      bool is_inserted = invokes_.insert(accessor, tag);
      if (is_inserted) {
        accessor->second = 1;
      } else {
        continue;
      }
    }
    break;
  }
  return accessor->second <= number_of_recalls_;
}

void KTimesReconnectionStorageStrategy::reset(const Tag &tag) {
  // intentionally don't care about status of erasing
  invokes_.erase(tag);
}

KTimesReconnectionStorageStrategy::Tag
KTimesReconnectionStorageStrategy::makeTag(const Tag &prefix) {
  uint64_t gotten_value = tag_counter++;
  return prefix + std::to_string(gotten_value);
}
