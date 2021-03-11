/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/field_validator.hpp"

#include <limits>
#include <string_view>

#include <fmt/core.h>
#include <boost/range/adaptor/indexed.hpp>
#include "common/bind.hpp"
#include "cryptography/crypto_provider/crypto_verifier.hpp"
#include "interfaces/common_objects/account.hpp"
#include "interfaces/common_objects/account_asset.hpp"
#include "interfaces/common_objects/amount.hpp"
#include "interfaces/common_objects/asset.hpp"
#include "interfaces/common_objects/domain.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "interfaces/queries/account_detail_pagination_meta.hpp"
#include "interfaces/queries/account_detail_record_id.hpp"
#include "interfaces/queries/asset_pagination_meta.hpp"
#include "interfaces/queries/query_payload_meta.hpp"
#include "interfaces/queries/tx_pagination_meta.hpp"
#include "multihash/multihash.hpp"
#include "validators/field_validator.hpp"
#include "validators/validation_error_helpers.hpp"

#include <initializer_list>
#include "utils/constexpr_to_string.hpp"

namespace {

  using namespace std::string_view_literals;
  using std::string_view;

  // we cannot return a char array from a function, therefore we need a wrapper
  template <unsigned N>
  struct String {
    char c[N];
//    constexpr operator (char[N])()const{ return c; }
    constexpr operator string_view()const{return {c,N};}
  };

  /// https://stackoverflow.com/a/65440575/3743145
  template<unsigned ...Len>
  constexpr auto cat(const char (&...strings)[Len]) {
    constexpr unsigned N = (... + Len) - sizeof...(Len);
    String<N + 1> result = {};
    result.c[N] = '\0';

    char* dst = result.c;
    for (const char* src : {strings...}) {
      for (; *src != '\0'; src++, dst++) {
        *dst = *src;
      }
    }
    return result;
  }

  struct RegexValidator {
    constexpr RegexValidator(
        string_view name,
        string_view pattern,
        string_view format_description = "")
        : name_(name),
          pattern_(pattern),
          format_description_(format_description)
    {}

    std::optional<shared_model::validation::ValidationError> validate(
        std::string_view value) const {
      std::regex rex(pattern_.begin(),pattern_.end());
      if (not std::regex_match(value.begin(), value.end(), rex)) {
        return shared_model::validation::ValidationError(
            std::string(name_),
            {fmt::format("passed value: '{}' does not match regex '{}'. {}",
                         value,
                         pattern_,
                         format_description_)});
      }
      return std::nullopt;
    }

    constexpr std::string_view const& getPattern() const {
      return pattern_;
    }

   private:
    string_view name_;
    string_view pattern_;
    string_view format_description_;
  };

  constexpr char kAccountNamePattern[] = R"#([a-z_0-9]{1,32})#";
  constexpr RegexValidator kAccountNameValidator{"AccountName",kAccountNamePattern};

  constexpr char kAssetNamePattern[]{R"#([a-z_0-9]{1,32})#"};
  constexpr RegexValidator kAssetNameValidator{"AssetName", kAssetNamePattern};

  constexpr char kDomainPattern[]{R"#(([a-zA-Z]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*)#"
                                           R"#([a-zA-Z]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)#"};
  constexpr RegexValidator kDomainValidator{
      "Domain", kDomainPattern
      };
  constexpr char kIpV4Pattern[]{
      R"#(^((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3})#"
      R"#(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])))#"};
  constexpr char kPortPattern[] =
      R"#((6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0)$)#";
  constexpr auto kPeerAddressPattern = cat("(",kIpV4Pattern,")|(",kDomainPattern,"):",kPortPattern);
  constexpr RegexValidator kPeerAddressValidator{
      "PeerAddress", kPeerAddressPattern,
      "Field should have a valid 'host:port' format where host is "
      "IPv4 or a hostname following RFC1035, RFC1123 specifications"};

  constexpr auto kOptionalPortPattern = cat(":?",kPortPattern);
  constexpr RegexValidator kPortValidator{
      "IpPort", kOptionalPortPattern,
      "Field should have a valid 'port' or ':port' format"};

  constexpr auto kAccountIdPattern = cat(kAccountNamePattern,"\\@",kDomainPattern);
  constexpr RegexValidator kAccountIdValidator{"AccountId",kAccountIdPattern};

  constexpr auto kAssetIdPattern = cat(kAssetNamePattern,"\\#",kDomainPattern);
  constexpr RegexValidator kAssetIdValidator{"AssetId",kAssetIdPattern};

  constexpr RegexValidator kAccountDetailKeyValidator{"DetailKey",
                                                  R"([A-Za-z0-9_]{1,64})"};
  constexpr RegexValidator kRoleIdValidator{"RoleId", R"#([a-z_0-9]{1,32})#"};
  constexpr RegexValidator kHexValidator{
      "Hex", R"#(([0-9a-fA-F][0-9a-fA-F])*)#", "Hex encoded string expected"};

  constexpr auto kPublicKeyHexPattern{cat("[A-Fa-f0-9]{{1,",to_string<shared_model::crypto::CryptoVerifier::kMaxPublicKeySize * 2>.buf,"}}")};
  constexpr RegexValidator kPublicKeyHexValidator{"PublicKeyHex",kPublicKeyHexPattern};

  constexpr auto kSignatureHexPattern{cat("[A-Fa-f0-9]{{1,",to_string<shared_model::crypto::CryptoVerifier::kMaxSignatureSize * 2>.buf,"}}")};
  constexpr RegexValidator kSignatureHexValidator{"SignatureHex",kSignatureHexPattern};

  constexpr RegexValidator kEvmAddressValidator{
      "EvmHexAddress",
      R"#([0-9a-fA-F]{40})#",
      "Hex encoded 20-byte address expected"};
}  // namespace

namespace shared_model {
  namespace validation {
    FieldValidator::FieldValidator(std::shared_ptr<ValidatorsConfig> config,
                                   time_t future_gap,
                                   TimeFunction time_provider)
        : future_gap_(future_gap), time_provider_(time_provider) {}

    std::optional<ValidationError> FieldValidator::validateAccountId(
        const interface::types::AccountIdType &account_id) const {
      return kAccountIdValidator.validate(account_id);
    }

    std::optional<ValidationError> FieldValidator::validateAssetId(
        const interface::types::AssetIdType &asset_id) const {
      return kAssetIdValidator.validate(asset_id);
    }

    std::optional<ValidationError> FieldValidator::validateEvmHexAddress(
        std::string_view address) const {
      return kEvmAddressValidator.validate(address);
    }

    std::optional<ValidationError> FieldValidator::validateBytecode(
        interface::types::EvmCodeHexStringView input) const {
      return kHexValidator.validate(
          static_cast<std::string_view const &>(input));
    }

    std::optional<ValidationError> FieldValidator::validatePeer(
        const interface::Peer &peer) const {
      return aggregateErrors(
          "Peer",
          {},
          {validatePeerAddress(peer.address()), validatePubkey(peer.pubkey())});
    }

    std::optional<ValidationError> FieldValidator::validateAmount(
        const interface::Amount &amount) const {
      if (amount.sign() <= 0) {
        return ValidationError(
            "Amount", {"Invalid number, amount must be greater than 0"});
      }
      return std::nullopt;
    }

    std::optional<ValidationError> FieldValidator::validatePubkey(
        std::string_view pubkey) const {
      return shared_model::validation::validatePubkey(pubkey);
    }

    std::optional<ValidationError> FieldValidator::validatePeerAddress(
        const interface::types::AddressType &address) const {
      return kPeerAddressValidator.validate(address);
    }

    std::optional<ValidationError> FieldValidator::validatePort(
        const interface::types::AddressType &port) const {
      return kPortValidator.validate(port);
    }

    std::optional<ValidationError> FieldValidator::validateRoleId(
        const interface::types::RoleIdType &role_id) const {
      return kRoleIdValidator.validate(role_id);
    }

    std::optional<ValidationError> FieldValidator::validateAccountName(
        const interface::types::AccountNameType &account_name) const {
      return kAccountNameValidator.validate(account_name);
    }

    std::optional<ValidationError> FieldValidator::validateDomainId(
        const interface::types::DomainIdType &domain_id) const {
      return kDomainValidator.validate(domain_id);
    }

    std::optional<ValidationError> FieldValidator::validateDomain(
        const interface::Domain &domain) const {
      return aggregateErrors("Domain",
                             {},
                             {validateDomainId(domain.domainId()),
                              validateRoleId(domain.defaultRole())});
    }

    std::optional<ValidationError> FieldValidator::validateAssetName(
        const interface::types::AssetNameType &asset_name) const {
      return kAssetNameValidator.validate(asset_name);
    }

    std::optional<ValidationError> FieldValidator::validateAccountDetailKey(
        const interface::types::AccountDetailKeyType &key) const {
      return kAccountDetailKeyValidator.validate(key);
    }

    std::optional<ValidationError> FieldValidator::validateAccountDetailValue(
        const interface::types::AccountDetailValueType &value) const {
      if (value.size() > value_size) {
        return ValidationError(
            "AccountDetailValue",
            {fmt::format(
                "Detail value size should be less or equal '{}' characters",
                value_size)});
      }
      return std::nullopt;
    }

    std::optional<ValidationError>
    FieldValidator::validateOldAccountDetailValue(
        const std::optional<interface::types::AccountDetailValueType>
            &old_value) const {
      if (old_value) {
        return validateAccountDetailValue(old_value.value());
      }
      return std::nullopt;
    }

    std::optional<ValidationError> FieldValidator::validatePrecision(
        const interface::types::PrecisionType &precision) const {
      return std::nullopt;
    }

    std::optional<ValidationError> FieldValidator::validateRolePermission(
        const interface::permissions::Role &permission) const {
      if (not isValid(permission)) {
        return ValidationError("RolePermission",
                               {"Provided role permission does not exist"});
      }
      return std::nullopt;
    }

    std::optional<ValidationError> FieldValidator::validateGrantablePermission(
        const interface::permissions::Grantable &permission) const {
      if (not isValid(permission)) {
        return ValidationError(
            "GrantablePermission",
            {"Provided grantable permission does not exist"});
      }
      return std::nullopt;
    }

    std::optional<ValidationError> FieldValidator::validateQuorum(
        const interface::types::QuorumType &quorum) const {
      if (quorum < 1 or quorum > 128) {
        return ValidationError("Quorum",
                               {"Quorum should be within range [1, 128]"});
      }
      return std::nullopt;
    }

    std::optional<ValidationError> FieldValidator::validateCreatorAccountId(
        const interface::types::AccountIdType &account_id) const {
      return kAccountIdValidator.validate(account_id);
    }

    std::optional<ValidationError> FieldValidator::validateAccount(
        const interface::Account &account) const {
      return aggregateErrors("Account",
                             {},
                             {validateAccountId(account.accountId()),
                              validateDomainId(account.domainId()),
                              validateQuorum(account.quorum())});
    }

    std::optional<ValidationError> FieldValidator::validateCreatedTime(
        interface::types::TimestampType timestamp,
        interface::types::TimestampType now) const {
      if (now + future_gap_ < timestamp) {
        return ValidationError(
            "CreatedTime",
            {fmt::format(
                "sent from future, timestamp: {}, now: {}", timestamp, now)});
      } else if (now > kMaxDelay + timestamp) {
        return ValidationError(
            "CreatedTime",
            {fmt::format("too old, timestamp: {}, now: {}", timestamp, now)});
      }
      return std::nullopt;
    }

    std::optional<ValidationError> FieldValidator::validateCreatedTime(
        interface::types::TimestampType timestamp) const {
      return validateCreatedTime(timestamp, time_provider_());
    }

    std::optional<ValidationError> FieldValidator::validateCounter(
        const interface::types::CounterType &counter) const {
      if (counter <= 0) {
        return ValidationError(
            "Counter",
            {fmt::format("Counter should be > 0, passed value: {}", counter)});
      }
      return std::nullopt;
    }

    std::optional<ValidationError> FieldValidator::validateSignatureForm(
        const interface::Signature &signature) const {
      ValidationErrorCreator error_creator;
      error_creator |= kSignatureHexValidator.validate(signature.signedData());
      error_creator |= validatePubkey(signature.publicKey());
      return std::move(error_creator).getValidationError("Signature");
    }

    std::optional<ValidationError> FieldValidator::validateSignatures(
        const interface::types::SignatureRangeType &signatures,
        const crypto::Blob &source) const {
      ValidationErrorCreator error_creator;
      if (boost::empty(signatures)) {
        error_creator.addReason("Signatures are empty.");
      }

      for (auto signature : signatures | boost::adaptors::indexed(1)) {
        ValidationErrorCreator sig_error_creator;

        auto sig_format_error = validateSignatureForm(signature.value());
        sig_error_creator |= sig_format_error;

        if (not sig_format_error) {
          using namespace shared_model::interface::types;
          if (auto e = resultToOptionalError(
                  shared_model::crypto::CryptoVerifier::verify(
                      SignedHexStringView{signature.value().signedData()},
                      source,
                      PublicKeyHexStringView{signature.value().publicKey()}))) {
            sig_error_creator.addReason(e.value());
          }
        }
        error_creator |= std::move(sig_error_creator)
                             .getValidationErrorWithGeneratedName([&] {
                               return fmt::format("Signature #{} ({})",
                                                  signature.index(),
                                                  signature.value().toString());
                             });
      }
      return std::move(error_creator).getValidationError("Signatures list");
    }

    std::optional<ValidationError> FieldValidator::validateQueryPayloadMeta(
        const interface::QueryPayloadMeta &meta) const {
      return std::nullopt;
    }

    std::optional<ValidationError> FieldValidator::validateDescription(
        const interface::types::DescriptionType &description) const {
      if (description.size() > kMaxDescriptionSize) {
        return ValidationError(
            "Description",
            {fmt::format("Size should be less or equal '{}'.",
                         kMaxDescriptionSize)});
      }
      return std::nullopt;
    }

    std::optional<ValidationError> FieldValidator::validateBatchMeta(
        const interface::BatchMeta &batch_meta) const {
      return std::nullopt;
    }

    std::optional<ValidationError> FieldValidator::validateHeight(
        const interface::types::HeightType &height) const {
      if (height <= 0) {
        return ValidationError(
            "Height",
            {fmt::format("Should be > 0, passed value: {}.", height)});
      }
      return std::nullopt;
    }

    std::optional<ValidationError> FieldValidator::validateHash(
        const crypto::Hash &hash) const {
      if (hash.size() != hash_size) {
        return ValidationError(
            "Hash",
            {fmt::format(
                "Invalid size: {}, should be {}.", hash.size(), hash_size)});
      }
      return std::nullopt;
    }

    std::optional<ValidationError> validatePubkey(std::string_view pubkey) {
      return kPublicKeyHexValidator.validate(pubkey);
    }

    std::optional<ValidationError> validatePaginationMetaPageSize(
        const size_t &page_size) {
      if (page_size <= 0) {
        return ValidationError(
            "PageSize",
            {fmt::format("Passed value is {} ({}), while it must be a non-zero "
                         "positive.",
                         (page_size == 0 ? "zero" : "negative"),
                         page_size)});
      }
      return std::nullopt;
    }

    std::optional<ValidationError> validatePaginationOrdering(
        const interface::Ordering &ordering) {
      using Field = interface::Ordering::Field;
      using Direction = interface::Ordering::Direction;
      using OrderingEntry = interface::Ordering::OrderingEntry;

      OrderingEntry const *ptr = nullptr;
      size_t count = 0;
      ordering.get(ptr, count);

      for (size_t ix = 0; ix < count; ++ix) {
        OrderingEntry const &entry = ptr[ix];

        if (entry.field >= Field::kMaxValueCount) {
          return ValidationError(
              "Ordering", {fmt::format("Passed field value is unknown.")});
        }

        if (entry.direction >= Direction::kMaxValueCount) {
          return ValidationError(
              "Ordering", {fmt::format("Passed direction value is unknown")});
        }
      }
      return std::nullopt;
    }

    std::optional<ValidationError> FieldValidator::validateTxPaginationMeta(
        const interface::TxPaginationMeta &tx_pagination_meta) const {
      using iroha::operator|;
      return aggregateErrors(
          "TxPaginationMeta",
          {},
          {validatePaginationMetaPageSize(tx_pagination_meta.pageSize()),
           tx_pagination_meta.firstTxHash() |
               [this](const auto &first_hash) {
                 return this->validateHash(first_hash);
               },
           validatePaginationOrdering(tx_pagination_meta.ordering())});
    }

    std::optional<ValidationError> FieldValidator::validateAsset(
        const interface::Asset &asset) const {
      return aggregateErrors("Asset",
                             {},
                             {validateDomainId(asset.domainId()),
                              validateAssetId(asset.assetId()),
                              validatePrecision(asset.precision())});
    }

    std::optional<ValidationError> FieldValidator::validateAccountAsset(
        const interface::AccountAsset &account_asset) const {
      return aggregateErrors("AccountAsset",
                             {},
                             {validateAccountId(account_asset.accountId()),
                              validateAssetId(account_asset.assetId()),
                              validateAmount(account_asset.balance())});
    }

    std::optional<ValidationError> FieldValidator::validateAssetPaginationMeta(
        const interface::AssetPaginationMeta &asset_pagination_meta) const {
      using iroha::operator|;
      return aggregateErrors(
          "AssetPaginationMeta",
          {},
          {validatePaginationMetaPageSize(asset_pagination_meta.pageSize()),
           asset_pagination_meta.firstAssetId() |
               [this](const auto &first_asset_id) {
                 return this->validateAssetId(first_asset_id);
               }});
    }

    std::optional<ValidationError>
    FieldValidator::validateAccountDetailRecordId(
        const interface::AccountDetailRecordId &record_id) const {
      return aggregateErrors("AccountDetailRecordId",
                             {},
                             {validateAccountId(record_id.writer()),
                              validateAccountDetailKey(record_id.key())});
    }

    std::optional<ValidationError>
    FieldValidator::validateAccountDetailPaginationMeta(
        const interface::AccountDetailPaginationMeta &pagination_meta) const {
      using iroha::operator|;
      return aggregateErrors(
          "AccountDetailPaginationMeta",
          {},
          {validatePaginationMetaPageSize(pagination_meta.pageSize()),
           pagination_meta.firstRecordId() |
               [this](const auto &first_record_id) {
                 return this->validateAccountDetailRecordId(first_record_id);
               }});
    }

  }  // namespace validation
}  // namespace shared_model
