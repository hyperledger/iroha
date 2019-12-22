/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_FIELD_VALIDATOR_HPP
#define IROHA_SHARED_MODEL_FIELD_VALIDATOR_HPP

#include <regex>

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
      FieldValidator(std::shared_ptr<ValidatorsConfig> config,
                     time_t future_gap = kDefaultFutureGap,
                     TimeFunction time_provider = [] {
                       return iroha::time::now();
                     });

      boost::optional<ValidationError> validateAccountId(
          const interface::types::AccountIdType &account_id) const;

      boost::optional<ValidationError> validateAssetId(
          const interface::types::AssetIdType &asset_id) const;

      boost::optional<ValidationError> validatePeer(
          const interface::Peer &peer) const;

      boost::optional<ValidationError> validateAmount(
          const interface::Amount &amount) const;

      boost::optional<ValidationError> validatePubkey(
          const interface::types::PubkeyType &pubkey) const;

      boost::optional<ValidationError> validatePeerAddress(
          const interface::types::AddressType &address) const;

      boost::optional<ValidationError> validateRoleId(
          const interface::types::RoleIdType &role_id) const;

      boost::optional<ValidationError> validateAccountName(
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
      boost::optional<ValidationError> validateDomainId(
          const interface::types::DomainIdType &domain_id) const;

      boost::optional<ValidationError> validateDomain(
          const interface::Domain &domain) const;

      boost::optional<ValidationError> validateAssetName(
          const interface::types::AssetNameType &asset_name) const;

      boost::optional<ValidationError> validateAccountDetailKey(
          const interface::types::AccountDetailKeyType &key) const;

      boost::optional<ValidationError> validateAccountDetailValue(
          const interface::types::AccountDetailValueType &value) const;

      boost::optional<ValidationError> validateOldAccountDetailValue(
          const boost::optional<interface::types::AccountDetailValueType>
              &old_value) const;

      boost::optional<ValidationError> validatePrecision(
          const interface::types::PrecisionType &precision) const;

      boost::optional<ValidationError> validateRolePermission(
          const interface::permissions::Role &permission) const;

      boost::optional<ValidationError> validateGrantablePermission(
          const interface::permissions::Grantable &permission) const;

      boost::optional<ValidationError> validateQuorum(
          const interface::types::QuorumType &quorum) const;

      boost::optional<ValidationError> validateCreatorAccountId(
          const interface::types::AccountIdType &account_id) const;

      boost::optional<ValidationError> validateAccount(
          const interface::Account &account) const;

      /**
       * Validate timestamp against now
       */
      boost::optional<ValidationError> validateCreatedTime(
          interface::types::TimestampType timestamp,
          interface::types::TimestampType now) const;

      /**
       * Validate timestamp against time_provider_
       */
      boost::optional<ValidationError> validateCreatedTime(
          interface::types::TimestampType timestamp) const;

      boost::optional<ValidationError> validateCounter(
          const interface::types::CounterType &counter) const;

      boost::optional<ValidationError> validateSignatureForm(
          const interface::Signature &signature) const;

      boost::optional<ValidationError> validateSignatures(
          const interface::types::SignatureRangeType &signatures,
          const crypto::Blob &source) const;

      boost::optional<ValidationError> validateQueryPayloadMeta(
          const interface::QueryPayloadMeta &meta) const;

      boost::optional<ValidationError> validateDescription(
          const interface::types::DescriptionType &description) const;

      boost::optional<ValidationError> validateBatchMeta(
          const interface::BatchMeta &description) const;

      boost::optional<ValidationError> validateHeight(
          const interface::types::HeightType &height) const;

      boost::optional<ValidationError> validateHash(
          const crypto::Hash &hash) const;

      boost::optional<ValidationError> validateTxPaginationMeta(
          const interface::TxPaginationMeta &tx_pagination_meta) const;

      boost::optional<ValidationError> validateAccountAsset(
          const interface::AccountAsset &account_asset) const;

      boost::optional<ValidationError> validateAsset(
          const interface::Asset &asset) const;

      boost::optional<ValidationError> validateAssetPaginationMeta(
          const interface::AssetPaginationMeta &asset_pagination_meta) const;

      boost::optional<ValidationError> validateAccountDetailRecordId(
          const interface::AccountDetailRecordId &record_id) const;

      boost::optional<ValidationError> validateAccountDetailPaginationMeta(
          const interface::AccountDetailPaginationMeta &pagination_meta) const;

     private:
      // gap for future transactions
      time_t future_gap_;
      // time provider callback
      TimeFunction time_provider_;

     public:
      // max-delay between tx creation and validation
      static constexpr auto kMaxDelay =
          std::chrono::hours(24) / std::chrono::milliseconds(1);
      // default value for future_gap field of FieldValidator
      static constexpr auto kDefaultFutureGap =
          std::chrono::minutes(5) / std::chrono::milliseconds(1);

      // size of key
      static const size_t public_key_size;
      static const size_t signature_size;
      static const size_t hash_size;
      static const size_t value_size;
      size_t max_description_size;
    };

    boost::optional<ValidationError> validatePubkey(
        const interface::types::PubkeyType &pubkey);

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_FIELD_VALIDATOR_HPP
