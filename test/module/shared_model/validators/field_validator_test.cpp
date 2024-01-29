/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <limits>
#include <memory>
#include <unordered_set>

#include <gmock/gmock-matchers.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/dynamic_message.h>
#include <boost/format.hpp>
#include <boost/range/algorithm.hpp>
#include <boost/range/join.hpp>
#include <optional>
#include "block.pb.h"

#include "backend/protobuf/batch_meta.hpp"
#include "backend/protobuf/common_objects/peer.hpp"
#include "backend/protobuf/permissions.hpp"
#include "backend/protobuf/queries/proto_query_payload_meta.hpp"
#include "backend/protobuf/queries/proto_tx_pagination_meta.hpp"
#include "builders/protobuf/queries.hpp"
#include "builders/protobuf/transaction.hpp"
#include "cryptography/crypto_provider/crypto_verifier.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "module/shared_model/validators/validators_fixture.hpp"
#include "validators/field_validator.hpp"
#include "validators/validation_error_output.hpp"

using namespace shared_model;

class FieldValidatorTest : public ValidatorsTest {
  validation::FieldValidator field_validator;

 protected:
  // Function which performs validation
  using ValidationFunction =
      std::function<std::optional<validation::ValidationError>()>;
  // Function which initializes field, allows to have one type when dealing
  // with various types of fields
  using InitFieldFunction = std::function<void()>;

  // Gaps for checking transactions from future
  static auto constexpr nearest_future =
      std::chrono::minutes(3) / std::chrono::milliseconds(1);
  static auto constexpr far_future =
      std::chrono::minutes(30) / std::chrono::milliseconds(1);

  /**
   * FieldTestCase is a struct that represents one value of some field,
   * and expected validation result.
   */
  struct FieldTestCase {
    std::string name;
    InitFieldFunction init_func;
    bool value_is_valid;
    std::string expected_message;
  };

  // Returns string containing field name and test case name for debug output
  std::string testFailMessage(const std::string &field_name,
                              const std::string &testcase_name) const {
    return (boost::format("Field: %s\nTest Case: %s\n") % field_name
            % testcase_name)
        .str();
  }

 public:
  FieldValidatorTest() : field_validator(iroha::test::kTestsValidatorsConfig) {
    field_validators.insert(makeValidator("public_key",
                                          &FieldValidator::validatePubkey,
                                          &FieldValidatorTest::public_key,
                                          public_key_test_cases));

    for (const auto &field : {"role_name", "default_role", "role_id"}) {
      field_validators.insert(makeValidator(field,
                                            &FieldValidator::validateRoleId,
                                            &FieldValidatorTest::role_name,
                                            role_name_test_cases));
    }
    for (const auto &field : {"account_id",
                              "src_account_id",
                              "dest_account_id",
                              "creator_account_id"}) {
      field_validators.insert(makeValidator(field,
                                            &FieldValidator::validateAccountId,
                                            &FieldValidatorTest::account_id,
                                            account_id_test_cases));
    }

    field_validators.insert(makeValidator("description",
                                          &FieldValidator::validateDescription,
                                          &FieldValidatorTest::description,
                                          description_test_cases));

    field_validators.insert(
        makeValidator("key",
                      &FieldValidator::validateAccountDetailKey,
                      &FieldValidatorTest::detail_key,
                      detail_key_test_cases));

    field_validators.insert(
        makeValidator("value",
                      &FieldValidator::validateAccountDetailValue,
                      &FieldValidatorTest::detail_value,
                      detail_value_test_cases));

    field_validators.insert(
        makeValidator("old_value",
                      &FieldValidator::validateOldAccountDetailValue,
                      &FieldValidatorTest::detail_old_value,
                      detail_old_value_test_cases));

    field_validators.insert(makeValidator("domain_id",
                                          &FieldValidator::validateDomainId,
                                          &FieldValidatorTest::domain_id,
                                          domain_id_test_cases));
    for (const auto &field : {"query_counter"}) {
      field_validators.insert(makeValidator(field,
                                            &FieldValidator::validateCounter,
                                            &FieldValidatorTest::counter,
                                            counter_test_cases));
    }

    field_validators.insert(makeValidator("quorum",
                                          &FieldValidator::validateQuorum,
                                          &FieldValidatorTest::quorum,
                                          quorum_test_cases));

    field_validators.insert(
        makeValidator("permission",
                      &FieldValidator::validateGrantablePermission,
                      &FieldValidatorTest::model_grantable_permission,
                      grantable_permission_test_cases));

    field_validators.insert(makeValidator("precision",
                                          &FieldValidator::validatePrecision,
                                          &FieldValidatorTest::precision,
                                          precision_test_cases));

    field_validators.insert(makeValidator("input",
                                          &FieldValidator::validateBytecode,
                                          &FieldValidatorTest::input,
                                          engine_input_cases));

    // TODO: add validation to all fields
    for (const auto &field : {"value",
                              "signature",
                              "commands",
                              "quorum",
                              "tx_hashes",
                              "tx_hash",
                              // permissions are always valid
                              "permissions",
                              "check_empty"}) {
      field_validators.insert(makeNullValidator(field));
    }
  }

  // To test one field, validation function is required,
  // which is always the same, and several test cases, which represent
  // various inputs
  using FieldTest = std::pair<ValidationFunction, std::vector<FieldTestCase>>;

  // Run all test cases for given field
  void runTestCases(const google::protobuf::FieldDescriptor *field) {
    auto field_name = field->name();
    // skip field, if already tested
    if (checked_fields.find(field_name) != checked_fields.end()) {
      return;
    }
    checked_fields.insert(field_name);

    // Will throw key exception in case new field is added
    FieldTest field_test;
    try {
      field_test = field_validators.at(field_name);
    } catch (const std::out_of_range &e) {
      FAIL() << "Missing field setter: " << field_name;
    }
    auto validate = field_test.first;
    for (auto &testcase : field_test.second) {
      // Initialize field
      testcase.init_func();
      // Perform validation
      auto error = validate();
      // if value supposed to be invalid, check that there is an error
      // and that error message is as expected.
      // If value supposed to be valid, check for empty error.
      if (!testcase.value_is_valid) {
        ASSERT_TRUE(error) << testFailMessage(field_name, testcase.name);
        // TODO IR-1183 add returned message check 29.03.2018
      } else {
        EXPECT_EQ(error, std::nullopt)
            << testFailMessage(field_name, testcase.name);
      }
    }
  }

 protected:
  // Because we use Protobuf reflection to generate fields by generating all
  // possible commands, some fields are checked several times
  // because they are present in several commands. To prevent that, this set
  // contains all already tested fields, and checked each time we try to test
  // a field
  std::unordered_set<std::string> checked_fields;

  /************************** TEST CASES ***************************/

  /**
   * Make expected message for test with wrong key size.
   * @param public_key - wrongly sized key
   * @return message expected from test
   */
  std::string makeMessageWrongKeySize(const std::string &public_key) {
    return (boost::format("Public key has wrong size, passed size: %d")
            % public_key.size())
        .str();
  }

  /// Create test case with field assignment initialization function
  template <typename F, typename V>
  FieldTestCase makeTestCase(const std::string &case_name,
                             F field,
                             const V &value,
                             bool valid,
                             const std::string &message) {
    return {
        case_name, [&, field, value] { this->*field = value; }, valid, message};
  }

  /// Create valid case with "valid" name, and empty message
  template <typename F, typename V>
  FieldTestCase makeValidCase(F field, const V &value) {
    return makeTestCase("valid", field, value, true, "");
  }

  /// Create invalid case with default message
  template <typename F>
  FieldTestCase makeInvalidCase(const std::string &case_name,
                                const std::string &field_name,
                                F field,
                                const std::string &value) {
    return makeTestCase(case_name, field, value, false, "");
  }

  /// Generate test cases for id types with name, separator, and domain
  template <typename F>
  std::vector<FieldTestCase> idTestCases(
      const std::string &field_name,
      F field,
      char separator,
      std::initializer_list<char> illegal_name_chars,
      size_t max_name_length) {
    auto fc = [](const auto &s, char c) {
      return (boost::format(s) % c).str();
    };

    auto f = [&](const auto &s) { return fc(s, separator); };

    std::vector<FieldTestCase> test_cases;

    auto add_valid = [&](auto c) {
      test_cases.emplace_back(makeValidCase(field, std::move(c)));
    };

    auto add_invalid = [&](const auto &name, auto c) {
      test_cases.emplace_back(
          this->makeInvalidCase(name, field_name, field, c));
    };

    // general cases
    add_valid(f("name%cdomain"));
    add_invalid("empty_string", "");
    add_invalid(f("missing_%c"), "absdomain");
    add_invalid(f("double_%c"), f("abs%1$cwhoops%1$cdomain"));

    // name cases
    add_invalid("missing_name", f("%cdomain"));
    for (char i : illegal_name_chars) {
      add_invalid(fc("illegal_char_%c_in_name", i),
                  fc("ab%cs", i) + f("%cdomain"));
    }
    add_valid(std::string(max_name_length, 'a') + f("%cdomain"));
    add_invalid("name_too_long",
                std::string(max_name_length + 1, 'a') + f("%cdomain"));
    add_invalid("name_way_too_long",
                std::string(max_name_length * 2, 'a') + f("%cdomain"));

    // domain cases
    static const std::vector<char> kIllegalAssetNameChars{{'_', '@', ' ', '#'}};
    static const size_t kMaxDomainLabelLength = 63;
    add_invalid("missing_domain", f("name%c"));
    for (char i : kIllegalAssetNameChars) {
      add_invalid(fc("illegal_char_%c_in_domain", i),
                  f("name%c") + fc("do%cmain", i));
    }
    add_valid(f("name%c") + std::string(kMaxDomainLabelLength, 'a'));
    add_invalid("domain_label_too_long",
                f("name%c") + std::string(kMaxDomainLabelLength + 1, 'a'));
    add_invalid("domain_label_way_too_long",
                f("name%c") + std::string(kMaxDomainLabelLength * 2, 'a'));
    add_invalid("domain_starts_with_digit", f("abs%c3domain"));
    add_invalid("domain_starts_with_dash", f("abs%c-domain"));
    add_invalid("domain_ends_with_dash", f("abs%cdomain-"));
    add_invalid("domain_label_starts_with_dash", f("abs%caa.-domain"));
    add_invalid("domain_label_ends_with_dash", f("abs%cdomain-.aa"));
    add_invalid("domain_double_dot", f("abs%cdomain..aa"));

    return test_cases;
  }

  std::vector<FieldTestCase> account_id_test_cases = idTestCases(
      "account_id", &FieldValidatorTest::account_id, '@', {'A', '-', ' '}, 32);

  std::vector<FieldTestCase> asset_id_test_cases = idTestCases(
      "asset_id", &FieldValidatorTest::asset_id, '#', {'A', '-', ' '}, 32);

  std::vector<FieldTestCase> description_test_cases = {
      makeValidCase(&FieldValidatorTest::description, ""),
  };

  std::vector<FieldTestCase> callee_cases{
      {"too big", [&] { callee = std::string(42, 'a'); }, false, ""},
      {"too small", [&] { callee = std::string(38, 'a'); }, false, ""},
      {"size doesnt matter", [&] { callee.reset(); }, true, ""},
      {"size-zero", [&] { callee = ""; }, false, ""},
      {"just fine", [&] { callee = std::string(40, 'a'); }, true, ""},
      {"garbage", [&] { callee = std::string(40, 'z'); }, false, ""}};

  std::vector<FieldTestCase> engine_input_cases{
      {"not hex", [&] { input = "not hex"sv; }, false, ""},
      {"hex", [&] { input = "600D"sv; }, true, ""}};

  std::vector<FieldTestCase> amount_test_cases{
      {"valid_amount", [&] { amount = "100"; }, true, ""},
      {"zero_amount",
       [&] { amount = "0"; },
       false,
       "Amount must be greater than 0, passed value: 0"},
      {"negative_amount",
       [&] { amount = "-100"; },
       false,
       "Amount must be greater than 0, passed value: -100"},
      {"invalid_amount",
       [&] { amount = "very much"; },
       false,
       "Amount must be a number, passed value: \"very much\""}};

  /**
   * Make test case for invalid peer address.
   * @param case_name - test case name
   * @param address - peer address
   * @param pubkey - peer public key
   * @return test case for invalid peer address
   */
  FieldTestCase makeInvalidPeerAddressTestCase(const std::string &case_name,
                                               const std::string &address,
                                               const std::string &pubkey) {
    return {case_name,
            [&, address, pubkey] {
              this->peer.set_address(address);
              this->peer.set_peer_key(pubkey);
            },
            false,
            ""};
  }

  /**
   * Make test case for valid peer address.
   * @param case_name - test case name
   * @param address - peer address
   * @param pubkey - peer public key
   * @return test case for valid peer address
   */
  FieldTestCase makeValidPeerAddressTestCase(const std::string &case_name,
                                             const std::string &address,
                                             const std::string &pubkey) {
    return {case_name,
            [&, address, pubkey] {
              this->peer.set_address(address);
              this->peer.set_peer_key(shared_model::crypto::Hash(pubkey).hex());
            },
            true,
            ""};
  }

  /**
   * Make test case for invalid peer public key.
   * @param case_name - test case name
   * @param address - peer address
   * @param pubkey - peer public key
   * @return test case for invalid peer public key
   */
  FieldTestCase makeInvalidPeerPubkeyTestCase(const std::string &case_name,
                                              const std::string &address,
                                              const std::string &pubkey) {
    return {case_name,
            [&, address, pubkey] {
              this->peer.set_address(address);
              this->peer.set_peer_key(pubkey);
            },
            false,
            makeMessageWrongKeySize(pubkey)};
  }

  /**
   * Make test case for invalid peer public key.
   * @param case_name - test case name
   * @param address - peer address
   * @param pubkey - peer public key
   * @return test case for invalid peer public key
   */
  FieldTestCase invalidPublicKeyTestCase(const std::string &case_name,
                                         const std::string &public_key) {
    return makeTestCase(case_name,
                        &FieldValidatorTest::public_key,
                        public_key,
                        false,
                        makeMessageWrongKeySize(public_key));
  }

  std::vector<FieldTestCase> public_key_test_cases{
      makeValidCase(&FieldValidatorTest::public_key, std::string(64, '0')),
      invalidPublicKeyTestCase(
          "too long public key",
          std::string(
              shared_model::crypto::CryptoVerifier::kMaxPublicKeySize * 2 + 2,
              '0')),
      invalidPublicKeyTestCase("empty_string", "")};

  std::vector<FieldTestCase> peer_test_cases{
      // clang-format off
      // ip addresses
      makeValidPeerAddressTestCase("zeros_ip","0.0.0.0:0", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeValidPeerAddressTestCase("max_ip", "255.255.255.255:65535", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeValidPeerAddressTestCase("common_ip","192.168.0.1:8080", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),

      makeInvalidPeerAddressTestCase("invalid_peer_address", "182.13.35.1:3040xx", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeInvalidPeerAddressTestCase("invalid symbol in ip", "-0.0.0.0:0", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeInvalidPeerAddressTestCase("too big number in ip", "256.256.256.255:65535", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeInvalidPeerAddressTestCase("too big port", "192.168.0.1:65536", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),

      // hostname
      makeValidPeerAddressTestCase("valid hostname with port", "abc.efg:0", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeValidPeerAddressTestCase("valid hostname with max port", "abc.efg.hij:65535", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeValidPeerAddressTestCase("hostname with hyphen", "a-hyphen.ru-i:8080", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeValidPeerAddressTestCase("common hostname with port", "altplus.com.jp:80", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeValidPeerAddressTestCase("max label length in hostname with port", "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad:8080", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeValidPeerAddressTestCase("max domain name length in hostname with port",
                                   "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad."
                                   "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad."
                                   "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad."
                                   "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad:256", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),


      makeInvalidPeerAddressTestCase("hostname starting with nonletter", "9.start.with.non.letter:0", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeInvalidPeerAddressTestCase("hostname starting with dash", "-startWithDash:65535", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeInvalidPeerAddressTestCase("hostname starting with at", "@.is.not.allowed:8080", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeInvalidPeerAddressTestCase("hostname with space", "no space is allowed:80", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeInvalidPeerAddressTestCase("hostname with too big port", "too.big.port:65536", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeInvalidPeerAddressTestCase("hostname with not allowed character", "some\u2063host:123", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeInvalidPeerAddressTestCase("hostname ending with hyphen", "endWith-:909", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeInvalidPeerAddressTestCase("hostname with too large label", "aLabelMustNotExceeds63charactersALabelMustNotExceeds63characters:9090", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeInvalidPeerAddressTestCase("hostname with more than 256 character domain",
      "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad."
      "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad."
      "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad."
      "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPadP:256", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeInvalidPeerAddressTestCase("empty address", "", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeInvalidPeerAddressTestCase("empty domain", ":6565", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),
      makeInvalidPeerAddressTestCase("empty domain two : symbols", "::6565:", std::string(crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, '0')),

      // invalid pubkey
      makeInvalidPeerPubkeyTestCase("invalid_peer_pubkey_length",
                                    "182.13.35.1:3040",
                                    std::string(200, '0')),
      makeInvalidPeerPubkeyTestCase(
          "invalid_peer_pubkey_empty", "182.13.35.1:3040", "")
      // clang-format on
  };

  /// Generate test cases for name types (account_name, asset_name, role_id)
  template <typename F>
  std::vector<FieldTestCase> nameTestCases(const std::string &field_name,
                                           F field) {
    return {makeTestCase("valid_name", field, "admin", true, ""),
            makeInvalidCase("empty_string", field_name, field, ""),
            makeInvalidCase("illegal_characters", field_name, field, "-math-"),
            makeInvalidCase("name_too_long",
                            field_name,
                            field,
                            "long_long_long_long_long_long_name")};
  }

  std::vector<FieldTestCase> role_name_test_cases =
      nameTestCases("role_id", &FieldValidatorTest::role_name);

  std::vector<FieldTestCase> account_name_test_cases =
      nameTestCases("account_name", &FieldValidatorTest::account_name);

  std::vector<FieldTestCase> asset_name_test_cases =
      nameTestCases("asset_name", &FieldValidatorTest::asset_name);

  /// domain_id
  std::vector<FieldTestCase> domainIdTestCases() {
    auto true_case = [&](const auto &name, const auto &case_value) {
      return this->makeTestCase(
          name, &FieldValidatorTest::domain_id, case_value, true, "");
    };
    auto false_case = [&](const auto &name, const auto &case_value) {
      return this->makeTestCase(
          name, &FieldValidatorTest::domain_id, case_value, false, "");
    };
    return {
        // clang-format off
      true_case("one_letter", "a"),
      true_case("two_letter", "ab"),
      true_case("period_separated", "abc.efg"),
      true_case("multiple_periods_separated", "abc.efg.hij"),
      true_case("with_numbers", "u9EEA432F"),
      true_case("with_hyphen", "a-hyphen"),
      true_case("with_63_character", "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad"),
      true_case("ending_with_digit","endWith0"),
      true_case("max_long_domain",
                 "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad."
                 "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad."
                 "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad."
                 "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad"),

      false_case("space", " "),
      false_case("start_with_digit", "9start.with.non.letter"),
      false_case("start_with_dash", "-startWithDash"),
      false_case("with_@", "@.is.not.allowed"),
      false_case("with_space","no space is allowed"),
      false_case("end_with_hyphen", "endWith-"),
      false_case("label_ending_with_hyphen","label.endedWith-.is.not.allowed"),
      false_case("too_long_label","aLabelMustNotExceeds63charactersALabelMustNotExceeds63characters"),
      false_case("too_long_domain",
                 "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad."
                 "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad."
                 "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad."
                 "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPadP")
        // clang-format on
    };
  }
  std::vector<FieldTestCase> domain_id_test_cases = domainIdTestCases();

  std::vector<FieldTestCase> permissions_test_cases{
      makeValidCase(&FieldValidatorTest::role_permission,
                    iroha::protocol::RolePermission::can_append_role)};

  std::vector<FieldTestCase> counter_test_cases{
      makeValidCase(&FieldValidatorTest::counter, 5),
      makeTestCase("zero_counter",
                   &FieldValidatorTest::counter,
                   0,
                   false,
                   "Counter should be > 0, passed value: 0")};
  std::vector<FieldTestCase> created_time_test_cases{
      makeValidCase(&FieldValidatorTest::created_time, iroha::time::now()),
      makeValidCase(&FieldValidatorTest::created_time,
                    iroha::time::now() + nearest_future),
      makeTestCase(
          "invalid due to far future",
          &FieldValidatorTest::created_time,
          iroha::time::now() + far_future,
          false,
          "bad timestamp: sent from future, timestamp: [0-9]+, now: [0-9]+")};

  std::vector<FieldTestCase> detail_key_test_cases{
      makeValidCase(&FieldValidatorTest::detail_key, "happy"),
      makeInvalidCase(
          "empty_string", "key", &FieldValidatorTest::detail_key, ""),
      makeInvalidCase(
          "illegal_char", "key", &FieldValidatorTest::detail_key, "hi-there")};

  std::vector<FieldTestCase> detail_value_test_cases{
      makeValidCase(&FieldValidatorTest::detail_value, "valid value"),
      makeValidCase(&FieldValidatorTest::detail_value, std::string(4096, '0')),
      makeValidCase(&FieldValidatorTest::detail_value, ""),
      makeInvalidCase(
          "long_value",
          "value",
          &FieldValidatorTest::detail_value,
          // 5 Mb, value greater than can put into one setAccountDetail
          std::string(5 * 1024 * 1024, '0'))};

  std::vector<FieldTestCase> detail_old_value_test_cases{
      makeValidCase(&FieldValidatorTest::detail_old_value, std::nullopt),
      makeValidCase(&FieldValidatorTest::detail_old_value, "valid old value"),
      makeValidCase(&FieldValidatorTest::detail_old_value,
                    std::string(4096, '0')),
      makeValidCase(&FieldValidatorTest::detail_old_value, ""),
      makeInvalidCase("long_value",
                      "old_value",
                      &FieldValidatorTest::detail_old_value,
                      // 5 Mb, value greater than can put into one
                      // CompareAndSetAccountDetail
                      std::string(5 * 1024 * 1024, '0'))};

  std::vector<FieldTestCase> quorum_test_cases{
      makeValidCase(&FieldValidatorTest::quorum, 1),
      makeValidCase(&FieldValidatorTest::quorum, 128),
      makeTestCase(
          "too big quorum size", &FieldValidatorTest::quorum, 129, false, "")};

  template <typename PermType, typename F>
  std::vector<FieldTestCase> permissionTestCases(F ValidatorsTest::*field) {
    std::vector<FieldTestCase> cases;

    // using PermType = shared_model::interface::permissions::Role;
    for (size_t i = 0; i < static_cast<size_t>(PermType::COUNT); ++i) {
      cases.push_back(makeValidCase(field, static_cast<PermType>(i)));
    }

    cases.push_back(makeTestCase("non-existing permission",
                                 field,
                                 static_cast<PermType>(PermType::COUNT),
                                 false,
                                 ""));

    return cases;
  }

  std::vector<FieldTestCase> role_permission_test_cases =
      permissionTestCases<shared_model::interface::permissions::Role>(
          &FieldValidatorTest::model_role_permission);
  std::vector<FieldTestCase> grantable_permission_test_cases =
      permissionTestCases<shared_model::interface::permissions::Grantable>(
          &FieldValidatorTest::model_grantable_permission);

  std::vector<FieldTestCase> meta_test_cases = [&]() {
    iroha::protocol::QueryPayloadMeta meta;
    meta.set_created_time(iroha::time::now());
    meta.set_creator_account_id("admin@test");
    meta.set_query_counter(5);
    std::vector<FieldTestCase> all_cases;
    all_cases.push_back(
        makeTestCase("meta test", &FieldValidatorTest::meta, meta, true, ""));
    return all_cases;
  }();

  std::vector<FieldTestCase> batch_meta_test_cases = [&]() {
    iroha::protocol::Transaction::Payload::BatchMeta meta;
    meta.set_type(iroha::protocol::Transaction::Payload::BatchMeta::BatchType::
                      Transaction_Payload_BatchMeta_BatchType_ATOMIC);
    meta.add_reduced_hashes("tst");
    std::vector<FieldTestCase> all_cases;
    all_cases.push_back(makeTestCase(
        "batch meta test", &FieldValidatorTest::batch_meta, meta, true, ""));
    return all_cases;
  }();

  std::vector<FieldTestCase> precision_test_cases{
      makeValidCase(&FieldValidatorTest::precision, 0),
      makeValidCase(&FieldValidatorTest::precision, 1),
      makeValidCase(&FieldValidatorTest::precision, 255),

      // The following cases are written because the type of PrecisionType is
      // going to be changed.

      // The case is disabled till PrecisionType will become a signed type,
      // now it is unsigned char.
      //      makeTestCase("negative precision",
      //                   &FieldValidatorTest::precision,
      //                   -3,
      //                   false,
      //                   "negative precision"),

      // Disabled, because PrecisionType is 1 byte type. The case should be
      // enabled when PrecisionType will be 2 bytes int or more.
      //      makeTestCase("precision value is more than max",
      //                   &FieldValidatorTest::precision,
      //                   256,
      //                   false,
      //                   "more than max")
  };

  // TODO mboldyrev 27.11.2018, IR-25: add the test cases
  std::vector<FieldTestCase> tx_pagination_meta_test_cases;

  /**************************************************************************/

  /// Create no-operation validator
  std::pair<std::string, FieldTest> makeNullValidator(
      const std::string &field_name) {
    return {field_name, {}};
  }

  /// Create validator with given field transformation
  template <typename F, typename V, typename T>
  std::pair<std::string, FieldTest> makeTransformValidator(
      const std::string &field_name,
      F field,
      V value,
      T transform,
      const std::vector<FieldTestCase> &cases) {
    return {field_name,
            {[&, field, value] {
               return (field_validator.*field)(transform(this->*value));
             },
             cases}};
  }

  /// Create validator with identity transformation
  template <typename F, typename V>
  std::pair<std::string, FieldTest> makeValidator(
      const std::string &field_name,
      F field,
      V value,
      const std::vector<FieldTestCase> &cases) {
    return makeTransformValidator(
        field_name, field, value, [](auto &&x) { return x; }, cases);
  }

  using FieldValidator = validation::FieldValidator;

  // register validation function and test cases
  std::unordered_map<std::string, FieldTest> field_validators{
      // Command fields
      makeValidator("asset_id",
                    &FieldValidator::validateAssetId,
                    &FieldValidatorTest::asset_id,
                    asset_id_test_cases),
      makeValidator("description",
                    &FieldValidator::validateDescription,
                    &FieldValidatorTest::description,
                    description_test_cases),
      makeTransformValidator(
          "amount",
          &FieldValidator::validateAmount,
          &FieldValidatorTest::amount,
          [](auto &&x) { return shared_model::interface::Amount(x); },
          amount_test_cases),
      makeValidator("caller",
                    &FieldValidator::validateAccountName,
                    &FieldValidatorTest::account_name,
                    account_name_test_cases),
      std::make_pair("callee",
                     FieldTest{[this] {
                                 if (callee) {
                                   return field_validator.validateEvmHexAddress(
                                       callee.value());
                                 }
                                 return decltype(
                                     field_validator.validateEvmHexAddress(
                                         callee.value())){};
                               },
                               callee_cases}),
      makeTransformValidator("peer",
                             &FieldValidator::validatePeer,
                             &FieldValidatorTest::peer,
                             [](auto &&x) { return proto::Peer(x); },
                             peer_test_cases),
      makeValidator("account_name",
                    &FieldValidator::validateAccountName,
                    &FieldValidatorTest::account_name,
                    account_name_test_cases),
      makeValidator("writer",
                    &FieldValidator::validateAccountId,
                    &FieldValidatorTest::account_id,
                    account_id_test_cases),
      makeValidator("domain_id",
                    &FieldValidator::validateDomainId,
                    &FieldValidatorTest::domain_id,
                    domain_id_test_cases),
      makeValidator("asset_name",
                    &FieldValidator::validateAssetName,
                    &FieldValidatorTest::asset_name,
                    asset_name_test_cases),
      makeValidator("height",
                    &FieldValidator::validateHeight,
                    &FieldValidatorTest::counter,
                    counter_test_cases),
      makeValidator(
          "created_time",
          static_cast<std::optional<validation::ValidationError> (
              FieldValidator::*)(interface::types::TimestampType) const>(
              &FieldValidator::validateCreatedTime),
          &FieldValidatorTest::created_time,
          created_time_test_cases),
      makeTransformValidator(
          "meta",
          &FieldValidator::validateQueryPayloadMeta,
          &FieldValidatorTest::meta,
          [](auto &&x) { return shared_model::proto::QueryPayloadMeta(x); },
          meta_test_cases),
      makeValidator("description",
                    &FieldValidator::validateDescription,
                    &FieldValidatorTest::description,
                    description_test_cases),
      makeTransformValidator(
          "batch",
          &FieldValidator::validateBatchMeta,
          &FieldValidatorTest::batch_meta,
          [](auto &&x) { return shared_model::proto::BatchMeta(x); },
          batch_meta_test_cases),
      makeTransformValidator(
          "pagination_meta",
          &FieldValidator::validateTxPaginationMeta,
          &FieldValidatorTest::tx_pagination_meta,
          [](auto &&x) { return proto::TxPaginationMeta(x); },
          tx_pagination_meta_test_cases),
      std::make_pair("type", FieldTest{[] { return std::nullopt; }, {}})};
};

/**
 * @given field values from test cases
 * @when field validator is invoked on command's fields
 * @then field validator correctly rejects invalid values, and provides
 * meaningful message
 */
TEST_F(FieldValidatorTest, CommandFieldsValidation) {
  iroha::protocol::Transaction proto_tx;
  auto payload = proto_tx.mutable_payload();

  // iterate over all commands in transaction
  iterateContainer(
      [] { return iroha::protocol::Command::descriptor(); },
      [&](auto field) {
        // Add new command to transaction
        auto command = payload->mutable_reduced_payload()->add_commands();
        //  // Set concrete type for new command
        return command->GetReflection()->MutableMessage(command, field);
      },
      [this](auto field, auto command) { this->runTestCases(field); },
      [] {});
}

/**
 * @given field values from test cases
 * @when field validator is invoked on transaction's fields
 * @then field validator correctly rejects invalid values, and provides
 * meaningful message
 */
TEST_F(FieldValidatorTest, TransactionFieldsValidation) {
  auto proto_tx = std::make_shared<iroha::protocol::Transaction>();
  proto_tx->add_signatures();  // at least one signature in message
  proto_tx->mutable_payload()->mutable_reduced_payload()->add_commands();
  // iterate over all fields in transaction
  iterateContainerRecursive(
      proto_tx,
      field_validators,
      [this](auto field, auto transaction_field) { this->runTestCases(field); },
      [] {});
}

/**
 * @given field values from test cases
 * @when field validator is invoked on query's fields
 * @then field validator correctly rejects invalid values, and provides
 * meaningful message
 */
TEST_F(FieldValidatorTest, QueryFieldsValidation) {
  iroha::protocol::Query qry;
  auto payload = qry.mutable_payload();
  // iterate over all field in query
  iterateContainer(
      [] {
        return iroha::protocol::Query::Payload::descriptor()->FindOneofByName(
            "query");
      },
      [&](auto field) {
        // Set concrete type for new query
        return payload->GetReflection()->MutableMessage(payload, field);
      },
      [this](auto field, auto query) { this->runTestCases(field); },
      [] {});
}

/**
 * @given field values from test cases
 * @when field validator is invoked on query container's fields
 * @then field validator correctly rejects invalid values, and provides
 * meaningful message
 */
TEST_F(FieldValidatorTest, QueryContainerFieldsValidation) {
  iroha::protocol::Query query_tx;

  // iterate over all fields in transaction
  iterateContainer(
      [] { return iroha::protocol::Query::descriptor(); },
      [&](auto field) {
        return query_tx.GetReflection()->MutableMessage(&query_tx, field);
      },
      [this](auto field, auto) {
        // Skip oneof types
        if (field->containing_oneof()
            == iroha::protocol::Query::Payload::descriptor()->FindOneofByName(
                   "query")) {
          return;
        }
        this->runTestCases(field);
      },
      [] {});
}
