/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_ordering.hpp"

#include <gtest/gtest.h>

using namespace shared_model::interface;

struct OrderingTest : public ::testing::Test {
  void checkCount(Ordering const &target, size_t expected_count) {
    Ordering::OrderingEntry const *entries;
    size_t count;
    target.get(entries, count);
    EXPECT_EQ(count, expected_count);
  }

  template <size_t Count>
  void checkValues(Ordering const &target,
                   std::pair<Ordering::Field, Ordering::Direction> const (
                       &expected)[Count]) {
    Ordering::OrderingEntry const *entries;
    size_t count;
    target.get(entries, count);

    EXPECT_EQ(Count, count);
    for (size_t ix = 0; ix < count; ++ix) {
      auto const &ref_item = expected[ix];
      auto const &target_item = entries[ix];

      EXPECT_EQ(ref_item.first, target_item.field);
      EXPECT_EQ(ref_item.second, target_item.direction);
    }
  }
};

/**
 * @given two insertions CreatedTime-ASC and Position-DESC
 * @then OrderingImpl will contain exactly these ordering fields
   @and order will be the same
*/
TEST_F(OrderingTest, BasicOrder) {
  shared_model::proto::OrderingImpl impl;
  impl.append(Ordering::Field::kCreatedTime, Ordering::Direction::kAscending);
  impl.append(Ordering::Field::kPosition, Ordering::Direction::kDescending);

  checkValues(
      impl,
      {
          {Ordering::Field::kCreatedTime, Ordering::Direction::kAscending},
          {Ordering::Field::kPosition, Ordering::Direction::kDescending},
      });
}

/**
 * @given four insertions with bad fields of different kind
 * @then OrderingImpl will contain 0 ordering items
 */
TEST_F(OrderingTest, BadValues) {
  shared_model::proto::OrderingImpl impl;
  impl.append(Ordering::Field(555), Ordering::Direction(555));
  impl.append(Ordering::Field::kUnknownValue,
              Ordering::Direction::kUnknownValue);
  impl.append(Ordering::Field::kCreatedTime,
              Ordering::Direction::kUnknownValue);
  impl.append(Ordering::Field::kUnknownValue, Ordering::Direction::kAscending);

  checkCount(impl, 0);
}

/**
 * @given several insertions with bad data
 * @and two correct data insertions Pos-ASC and CT-ASC
 * @then OrderingImpl will contain exactly 2 entries Pos-ASC and CT-ASC.
 */
TEST_F(OrderingTest, MixedValues) {
  shared_model::proto::OrderingImpl impl;
  impl.append(Ordering::Field(555), Ordering::Direction(555));
  impl.append(Ordering::Field::kUnknownValue,
              Ordering::Direction::kUnknownValue);
  impl.append(Ordering::Field::kCreatedTime,
              Ordering::Direction::kUnknownValue);
  impl.append(Ordering::Field::kUnknownValue, Ordering::Direction::kAscending);
  impl.append(Ordering::Field::kPosition, Ordering::Direction::kAscending);
  impl.append(Ordering::Field::kCreatedTime, Ordering::Direction::kAscending);

  checkValues(
      impl,
      {
          {Ordering::Field::kPosition, Ordering::Direction::kAscending},
          {Ordering::Field::kCreatedTime, Ordering::Direction::kAscending},
      });
}

/**
 * @given several insertions CT-ASC, CT-DESC, POS-DESC, CT-ASC, POS-ASC, CT-DESC
 * @then OrderingImpl will contain exactly 2 entries of the first correct type
 * of insertion CT-ASC and POS-DESC
 */
TEST_F(OrderingTest, Reinsertions) {
  shared_model::proto::OrderingImpl impl;
  impl.append(Ordering::Field::kCreatedTime, Ordering::Direction::kAscending);
  impl.append(Ordering::Field::kCreatedTime, Ordering::Direction::kDescending);
  impl.append(Ordering::Field::kPosition, Ordering::Direction::kDescending);
  impl.append(Ordering::Field::kCreatedTime, Ordering::Direction::kAscending);
  impl.append(Ordering::Field::kPosition, Ordering::Direction::kAscending);
  impl.append(Ordering::Field::kCreatedTime, Ordering::Direction::kDescending);

  checkValues(
      impl,
      {
          {Ordering::Field::kCreatedTime, Ordering::Direction::kAscending},
          {Ordering::Field::kPosition, Ordering::Direction::kDescending},
      });
}

/**
 * @given proto query with ordering douplicate POS-ASC
 * @then OrderingImpl will contain only 1 entry POS-ASC
 */
TEST_F(OrderingTest, ProtoDoubleValues) {
  iroha::protocol::Ordering proto_ordering;
  {
    auto sequence = proto_ordering.add_sequence();
    sequence->set_field(iroha::protocol::Field::kPosition);
    sequence->set_direction(iroha::protocol::Direction::kAscending);
  }
  {
    auto sequence = proto_ordering.add_sequence();
    sequence->set_field(iroha::protocol::Field::kPosition);
    sequence->set_direction(iroha::protocol::Direction::kAscending);
  }

  shared_model::proto::OrderingImpl impl(proto_ordering);
  checkValues(impl,
              {
                  {Ordering::Field::kPosition, Ordering::Direction::kAscending},
              });
}

/**
 * @given proto query with several unexpected values and two correct POS-ASC and
 * CT-ASC
 * @then OrderingImpl will contain exactly 2 correct entries POS-ASC and CT-ASC
 */
TEST_F(OrderingTest, ProtoMixedValues) {
  iroha::protocol::Ordering proto_ordering;
  {
    auto sequence = proto_ordering.add_sequence();
    sequence->set_field(iroha::protocol::Field(1001));
    sequence->set_direction(iroha::protocol::Direction(1002));
  }
  {
    auto sequence = proto_ordering.add_sequence();
    sequence->set_field(iroha::protocol::Field::kCreatedTime);
    sequence->set_direction(iroha::protocol::Direction(1002));
  }
  {
    auto sequence = proto_ordering.add_sequence();
    sequence->set_field(iroha::protocol::Field(555));
    sequence->set_direction(iroha::protocol::Direction::kAscending);
  }
  {
    auto sequence = proto_ordering.add_sequence();
    sequence->set_field(iroha::protocol::Field::kPosition);
    sequence->set_direction(iroha::protocol::Direction::kAscending);
  }
  {
    auto sequence = proto_ordering.add_sequence();
    sequence->set_field(iroha::protocol::Field::kCreatedTime);
    sequence->set_direction(iroha::protocol::Direction::kAscending);
  }

  shared_model::proto::OrderingImpl impl(proto_ordering);
  checkValues(
      impl,
      {
          {Ordering::Field::kPosition, Ordering::Direction::kAscending},
          {Ordering::Field::kCreatedTime, Ordering::Direction::kAscending},
      });
}
