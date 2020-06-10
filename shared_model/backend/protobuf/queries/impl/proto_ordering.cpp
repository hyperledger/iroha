/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_ordering.hpp"

#include <algorithm>
#include <cstring>

#include "common/mem_operations.hpp"

using namespace shared_model::proto;

namespace {
  shared_model::interface::Ordering::Field fromProto2Interface(
      iroha::protocol::Field value) {
    switch (value) {
      case iroha::protocol::Field::kCreatedTime:
        return shared_model::interface::Ordering::Field::kCreatedTime;

      case iroha::protocol::Field::kPosition:
        return shared_model::interface::Ordering::Field::kPosition;

      default: {
        return shared_model::interface::Ordering::Field::kUnknownValue;
      }
    }
  }

  shared_model::interface::Ordering::Direction fromProto2Interface(
      iroha::protocol::Direction value) {
    switch (value) {
      case iroha::protocol::Direction::kAscending:
        return shared_model::interface::Ordering::Direction::kAscending;

      case iroha::protocol::Direction::kDescending:
        return shared_model::interface::Ordering::Direction::kDescending;

      default: {
        return shared_model::interface::Ordering::Direction::kUnknownValue;
      }
    }
  }
}  // namespace

OrderingImpl::OrderingImpl() {
  reset();
}

OrderingImpl::OrderingImpl(OrderingImpl &&c) {
  copy(c);
}

OrderingImpl::OrderingImpl(OrderingImpl const &c) {
  copy(c);
}

OrderingImpl::OrderingImpl(iroha::protocol::Ordering const &proto_ordering) {
  reset();
  auto const &sequence = proto_ordering.sequence();
  for (auto const &entry : sequence) {
    if (count_ == (size_t)ModelType::Field::kMaxValueCount) {
      break;
    }

    appendUnsafe(fromProto2Interface(entry.field()),
                 fromProto2Interface(entry.direction()));
  }
}

void OrderingImpl::copy(OrderingImpl const &src) {
  iroha::memcpy(ordering_, src.ordering_);
  iroha::memcpy(inserted_, src.inserted_);
  count_ = src.count_;
}

void OrderingImpl::appendUnsafe(ModelType::Field field,
                                ModelType::Direction direction) {
  BOOST_ASSERT_MSG(count_ <= (size_t)ModelType::Field::kMaxValueCount,
                   "Count can not be more than max_count. Check logic.");

  if (field >= ModelType::Field::kUnknownValue) {
    return;
  }
  if (direction >= ModelType::Direction::kUnknownValue) {
    return;
  }

  if (!inserted_[(size_t)field]) {
    auto &entry = ordering_[count_++];
    entry.field = field;
    entry.direction = direction;

    inserted_[(size_t)field] = true;
  }
}

bool OrderingImpl::append(ModelType::Field field,
                          ModelType::Direction direction) {
  static_assert(sizeof(inserted_) / sizeof(inserted_[0])
                    == sizeof(ordering_) / sizeof(ordering_[0]),
                "inserted_ and ordering_ must be the same size.");

  if (field >= ModelType::Field::kUnknownValue) {
    return false;
  }
  if (direction >= ModelType::Direction::kUnknownValue) {
    return false;
  }

  appendUnsafe(field, direction);
  return true;
}

void OrderingImpl::reset() {
  iroha::memzero(ordering_);
  iroha::memzero(inserted_);
  count_ = 0;
}

void OrderingImpl::get(ModelType::OrderingEntry const *&orderingEntry,
                       size_t &count) const {
  orderingEntry = ordering_;
  count = count_;
}
