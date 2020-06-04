/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <cstring>

#include "interfaces/queries/ordering.hpp"

using namespace shared_model::interface;

namespace {

  char const *kFieldStrRepres[] = {"created time", "position"};
  static_assert(sizeof(kFieldStrRepres) / sizeof(*kFieldStrRepres)
                    == (size_t)Ordering::Field::kMaxValueCount,
                "String names must be the same size.");

  char const *kDirectionStrRepres[] = {"ascending", "descending"};
  static_assert(sizeof(kDirectionStrRepres) / sizeof(*kDirectionStrRepres)
                    == (size_t)Ordering::Direction::kMaxValueCount,
                "String names must be the same size.");

  char const *fromField2Str(Ordering::Field const val) {
    BOOST_ASSERT_MSG(val < Ordering::Field::kMaxValueCount,
                     "val can not be greater or equal than kMaxValueCount");
    return kFieldStrRepres[(size_t)val];
  }

  char const *fromDirection2Str(Ordering::Direction const val) {
    BOOST_ASSERT_MSG(val < Ordering::Direction::kMaxValueCount,
                     "val can not be greater or equal than kMaxValueCount");
    return kDirectionStrRepres[(size_t)val];
  }

}  // namespace

bool Ordering::operator==(const ModelType &rhs) const {
  OrderingEntry const *entries_1;
  size_t count_1;
  this->get(entries_1, count_1);

  OrderingEntry const *entries_2;
  size_t count_2;
  rhs.get(entries_2, count_2);

  return (count_1 == count_2)
      && (0 == memcmp(entries_1, entries_2, count_1 * sizeof(OrderingEntry)));
}

std::string Ordering::toString() const {
  OrderingEntry const *entries;
  size_t count;
  this->get(entries, count);

  auto pretty_builder = detail::PrettyStringBuilder().init("Ordering");

  for (uint64_t ix = 0; ix < count; ++ix) {
    auto const &entry = entries[ix];

    pretty_builder =
        pretty_builder.appendNamed("field", fromField2Str(entry.field))
            .appendNamed("direction", fromDirection2Str(entry.direction));
  }
  return pretty_builder.finalize();
}
