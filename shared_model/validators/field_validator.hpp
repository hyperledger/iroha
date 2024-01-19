/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_FIELD_VALIDATOR_HPP
#define IROHA_SHARED_MODEL_FIELD_VALIDATOR_HPP

#include <chrono>
#include <regex>

#include "cryptography/default_hash_provider.hpp"
#include "datetime/time.hpp"
#include "interfaces/base/signable.hpp"
#include "interfaces/permissions.hpp"
#include "interfaces/queries/query_payload_meta.hpp"
#include "validators/validation_error.hpp"
#include "validators/validators_common.hpp"

namespace shared_model {

  namespace interface {
    class Account;
    class AccountAsset;
    class AccountDetailPaginationMeta;
    class AccountDetailRecordId;
    class Amount;
    class Asset;
    class AssetPaginationMeta;
    class BatchMeta;
    class Domain;
    class Peer;
    class TxPaginationMeta;
  }  // namespace interface

  namespace validation {

    /**
     * Class that validates fields of commands, concrete queries, transaction,
     * and query
     */
    class FieldValidator {
     private:
      using TimeFunction = std::function<iroha::ts64_t()>;

     public:
      // todo igor-egorov 05.04.2018 IR-439 Remove ValidatorsConfig from
      // FieldValidator
      FieldValidator(std::shared_ptr<ValidatorsConfig> config,
                     time_t future_gap = kDefaultFutureGap,
                     TimeFunction time_provider = [] {
                       return iroha::time::now();
                     });

      std::optional<ValidationError> validateAccountId(
          const interface::types::AccountIdType &account_id) const;

      std::optional<ValidationError> validateAssetId(
          const interface::types::AssetIdType &asset_id) const;

      std::optional<ValidationError> validateDescription(
          const interface::types::DescriptionType &description) const;

      std::optional<ValidationError> validateEvmHexAddress(
          std::string_view address) const;

      std::optional<ValidationError> validateBytecode(
          interface::types::EvmCodeHexStringView input) const;

      std::optional<ValidationError> validatePeer(
          const interface::Peer &peer) const;

      std::optional<ValidationError> validateAmount(
          const interface::Amount &amount) const;

      std::optional<ValidationError> validatePubkey(
          std::string_view pubkey) const;

      std::optional<ValidationError> validatePeerAddress(
          const interface::types::AddressType &address) const;

      std::optional<ValidationError> validateRoleId(
          const interface::types::RoleIdType &role_id) const;

      std::optional<ValidationError> validateAccountName(
          const interface::types::AccountNameType &account_name) const;

      // clang-format off
      /**
       * Check if the given string `domain_id` is in valid domain syntax defined in
       * the RFC 1035 and 1123. Return the result of the validation.
       *
       * The domain syntax in RFC 1035 is given below:
       *
       *   <domain>      ::= <subdomain> | ” ”
       *   <subdomain>   ::= <label> | <subdomain> “.” <label>
       *   <label>       ::= <letter> [ [ <ldh-str> ] <let-dig> ]
       *   <ldh-str>     ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>
       *   <let-dig-hyp> ::= <let-dig> | “-”
       *   <let-dig>     ::= <letter> | <digit>
       *   <letter>      ::= any one of the 52 alphabetic characters A through Z in
       *                     upper case and a through z in lower case
       *   <digit>       ::= any one of the ten digits 0 through 9
       *
       * And the subsequent RFC 1123 disallows the root white space.
       *
       * If the validation is not successful reason is updated with corresponding message
       */
      // clang-format on
      std::optional<ValidationError> validateDomainId(
          const interface::types::DomainIdType &domain_id) const;

      std::optional<ValidationError> validateDomain(
          const interface::Domain &domain) const;

      std::optional<ValidationError> validateAssetName(
          const interface::types::AssetNameType &asset_name) const;

      std::optional<ValidationError> validateAccountDetailKey(
          const interface::types::AccountDetailKeyType &key) const;

      std::optional<ValidationError> validateAccountDetailValue(
          const interface::types::AccountDetailValueType &value) const;

      std::optional<ValidationError> validateOldAccountDetailValue(
          const std::optional<interface::types::AccountDetailValueType>
              &old_value) const;

      std::optional<ValidationError> validatePrecision(
          const interface::types::PrecisionType &precision) const;

      std::optional<ValidationError> validateRolePermission(
          const interface::permissions::Role &permission) const;

      std::optional<ValidationError> validateGrantablePermission(
          const interface::permissions::Grantable &permission) const;

      std::optional<ValidationError> validateQuorum(
          const interface::types::QuorumType &quorum) const;

      std::optional<ValidationError> validateCreatorAccountId(
          const interface::types::AccountIdType &account_id) const;

      std::optional<ValidationError> validateAccount(
          const interface::Account &account) const;

      /**
       * Validate timestamp against now
       */
      std::optional<ValidationError> validateCreatedTime(
          interface::types::TimestampType timestamp,
          interface::types::TimestampType now) const;

      /**
       * Validate timestamp against time_provider_
       */
      std::optional<ValidationError> validateCreatedTime(
          interface::types::TimestampType timestamp) const;

      std::optional<ValidationError> validateCounter(
          const interface::types::CounterType &counter) const;

      std::optional<ValidationError> validateSignatureForm(
          const interface::Signature &signature) const;

      std::optional<ValidationError> validateSignatures(
          const interface::types::SignatureRangeType &signatures,
          const crypto::Blob &source) const;

      std::optional<ValidationError> validateQueryPayloadMeta(
          const interface::QueryPayloadMeta &meta) const;

      std::optional<ValidationError> validateBatchMeta(
          const interface::BatchMeta &description) const;

      std::optional<ValidationError> validateHeight(
          const interface::types::HeightType &height) const;

      std::optional<ValidationError> validateHash(
          const crypto::Hash &hash) const;

      std::optional<ValidationError> validateTxPaginationMeta(
          const interface::TxPaginationMeta &tx_pagination_meta) const;

      std::optional<ValidationError> validateAccountAsset(
          const interface::AccountAsset &account_asset) const;

      std::optional<ValidationError> validateAsset(
          const interface::Asset &asset) const;

      std::optional<ValidationError> validateAssetPaginationMeta(
          const interface::AssetPaginationMeta &asset_pagination_meta) const;

      std::optional<ValidationError> validateAccountDetailRecordId(
          const interface::AccountDetailRecordId &record_id) const;

      std::optional<ValidationError> validateAccountDetailPaginationMeta(
          const interface::AccountDetailPaginationMeta &pagination_meta) const;

     private:
      // gap for future transactions
      time_t future_gap_;
      // time provider callback
      TimeFunction time_provider_;

      // max-delay between tx creation and validation
      std::chrono::milliseconds max_delay_;

     public:
      // default value for future_gap field of FieldValidator
      static constexpr auto kDefaultFutureGap =
          std::chrono::minutes(5) / std::chrono::milliseconds(1);

      // default value for future_gap field of FieldValidator
      static constexpr auto kDefaultMaxDelay =
          std::chrono::hours(24) / std::chrono::milliseconds(1);

      static constexpr size_t hash_size =
          crypto::DefaultHashProvider::kHashLength;
      /// limit for the set account detail size in bytes
      static constexpr size_t value_size = 4 * 1024 * 1024;
      static constexpr size_t kMaxDescriptionSize = 100 * 1024;  // 100K
    };

    std::optional<ValidationError> validatePubkey(
        shared_model::interface::types::PublicKeyHexStringView pubkey);

    std::optional<ValidationError> validatePubkey(std::string_view pubkey);

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_FIELD_VALIDATOR_HPP
