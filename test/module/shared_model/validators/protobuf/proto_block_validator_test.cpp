/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/protobuf/proto_block_validator.hpp"

#include <gmock/gmock-matchers.h>
#include <optional>
#include "block.pb.h"
#include "module/shared_model/validators/validators_fixture.hpp"
#include "validators/validation_error_output.hpp"

using testing::HasSubstr;

class ProtoBlockValidatorTest : public ValidatorsTest {
 public:
  shared_model::validation::ProtoBlockValidator validator;
};

/**
 * @given protocol block object with unset version field
 * @when validating this object
 * @then corresponding error is returned
 */
TEST_F(ProtoBlockValidatorTest, UnsetVersion) {
  iroha::protocol::Block invalid_block;

  auto error = validator.validate(invalid_block);
  ASSERT_TRUE(error);
  ASSERT_THAT(error->toString(), HasSubstr("Unknown block version"));
}

/**
 * @given valid protocol block object
 * @when validating this object
 * @then validation is successful
 */
TEST_F(ProtoBlockValidatorTest, ValidBlock) {
  iroha::protocol::Block valid_block;

  iroha::protocol::Block_v1 versioned_block;
  *valid_block.mutable_block_v1() = versioned_block;

  ASSERT_EQ(validator.validate(valid_block), std::nullopt);
}

/**
 * @given block object with invalid hash format in rejected hashes
 * @when validating this object
 * @then validation is failed
 */
TEST_F(ProtoBlockValidatorTest, BlockWithInvalidRejectedHash) {
  iroha::protocol::Block invalid_block;

  iroha::protocol::Block_v1 versioned_block;
  *versioned_block.mutable_payload()->add_rejected_transactions_hashes() =
      std::string("not_hex_value");
  *invalid_block.mutable_block_v1() = versioned_block;

  ASSERT_TRUE(validator.validate(invalid_block));
}

/**
 * @given block object with valid hash format in rejected hashes
 * @when validating this object
 * @then validation is successful
 */
TEST_F(ProtoBlockValidatorTest, BlockWithValidRejectedHash) {
  iroha::protocol::Block valid_block;

  iroha::protocol::Block_v1 versioned_block;
  *versioned_block.mutable_payload()->add_rejected_transactions_hashes() =
      std::string("123abc");
  *valid_block.mutable_block_v1() = versioned_block;

  ASSERT_EQ(validator.validate(valid_block), std::nullopt);
}

/**
 * @given block object with valid hash format previous block hash
 * @when validating this object
 * @then validation is successful
 */
TEST_F(ProtoBlockValidatorTest, BlockWithValidPrevHash) {
  iroha::protocol::Block valid_block;

  iroha::protocol::Block_v1 versioned_block;
  versioned_block.mutable_payload()->set_prev_block_hash("123abc");
  *valid_block.mutable_block_v1() = versioned_block;

  ASSERT_EQ(validator.validate(valid_block), std::nullopt);
}

/**
 * @given block object with invalid hash format previous block hash
 * @when validating this object
 * @then validation is failed
 */
TEST_F(ProtoBlockValidatorTest, BlockWithInvalidPrevHash) {
  iroha::protocol::Block invalid_block;

  iroha::protocol::Block_v1 versioned_block;
  versioned_block.mutable_payload()->set_prev_block_hash("not_hex");
  *invalid_block.mutable_block_v1() = versioned_block;

  ASSERT_TRUE(validator.validate(invalid_block));
}
