/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/field_validator.hpp"

#include <limits>

#include <boost/algorithm/string_regex.hpp>
#include <boost/format.hpp>
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "cryptography/crypto_provider/crypto_verifier.hpp"
#include "interfaces/common_objects/amount.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "interfaces/queries/account_asset_pagination_meta.hpp"
#include "interfaces/queries/query_payload_meta.hpp"
#include "interfaces/queries/tx_pagination_meta.hpp"
#include "validators/field_validator.hpp"

// TODO: 15.02.18 nickaleks Change structure to compositional IR-978

namespace shared_model {
  namespace validation {

    const std::string FieldValidator::account_name_pattern_ =
        R"#([a-z_0-9]{1,32})#";
    const std::string FieldValidator::asset_name_pattern_ =
        R"#([a-z_0-9]{1,32})#";
    const std::string FieldValidator::domain_pattern_ =
        R"#(([a-zA-Z]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)#";
    const std::string FieldValidator::ip_v4_pattern_ =
        R"#(^((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3})#"
        R"#(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])))#";
    const std::string FieldValidator::peer_address_pattern_ = "(("
        + ip_v4_pattern_ + ")|(" + domain_pattern_ + ")):"
        + R"#((6553[0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3}|0)$)#";
    const std::string FieldValidator::account_id_pattern_ =
        account_name_pattern_ + R"#(\@)#" + domain_pattern_;
    const std::string FieldValidator::asset_id_pattern_ =
        asset_name_pattern_ + R"#(\#)#" + domain_pattern_;
    const std::string FieldValidator::detail_key_pattern_ =
        R"([A-Za-z0-9_]{1,64})";
    const std::string FieldValidator::role_id_pattern_ = R"#([a-z_0-9]{1,32})#";

    const size_t FieldValidator::public_key_size =
        crypto::DefaultCryptoAlgorithmType::kPublicKeyLength;
    const size_t FieldValidator::signature_size =
        crypto::DefaultCryptoAlgorithmType::kSignatureLength;
    const size_t FieldValidator::hash_size =
        crypto::DefaultCryptoAlgorithmType::kHashLength;
    /// limit for the set account detail size in bytes
    const size_t FieldValidator::value_size = 4 * 1024 * 1024;
    const size_t FieldValidator::description_size = 64;

    const std::regex FieldValidator::account_name_regex_(account_name_pattern_);
    const std::regex FieldValidator::asset_name_regex_(asset_name_pattern_);
    const std::regex FieldValidator::domain_regex_(domain_pattern_);
    const std::regex FieldValidator::ip_v4_regex_(ip_v4_pattern_);
    const std::regex FieldValidator::peer_address_regex_(peer_address_pattern_);
    const std::regex FieldValidator::account_id_regex_(account_id_pattern_);
    const std::regex FieldValidator::asset_id_regex_(asset_id_pattern_);
    const std::regex FieldValidator::detail_key_regex_(detail_key_pattern_);
    const std::regex FieldValidator::role_id_regex_(role_id_pattern_);

    FieldValidator::FieldValidator(std::shared_ptr<ValidatorsConfig> config,
                                   time_t future_gap,
                                   TimeFunction time_provider)
        : future_gap_(future_gap), time_provider_(time_provider) {}

    void FieldValidator::validateAccountId(
        ReasonsGroupType &reason,
        const interface::types::AccountIdType &account_id) const {
      if (not std::regex_match(account_id, account_id_regex_)) {
        auto message =
            (boost::format("Wrongly formed account_id, passed value: '%s'. "
                           "Field should match regex '%s'")
             % account_id % account_id_pattern_)
                .str();
        reason.second.push_back(std::move(message));
      }
    }

    void FieldValidator::validateAssetId(
        ReasonsGroupType &reason,
        const interface::types::AssetIdType &asset_id) const {
      if (not std::regex_match(asset_id, asset_id_regex_)) {
        auto message = (boost::format("Wrongly formed asset_id, passed value: "
                                      "'%s'. Field should match regex '%s'")
                        % asset_id % asset_id_pattern_)
                           .str();
        reason.second.push_back(std::move(message));
      }
    }

    void FieldValidator::validatePeer(ReasonsGroupType &reason,
                                      const interface::Peer &peer) const {
      validatePeerAddress(reason, peer.address());
      validatePubkey(reason, peer.pubkey());
    }

    void FieldValidator::validateAmount(ReasonsGroupType &reason,
                                        const interface::Amount &amount) const {
      if (amount.intValue() <= 0) {
        auto message =
            (boost::format("Amount must be greater than 0, passed value: %d")
             % amount.intValue())
                .str();
        reason.second.push_back(message);
      }
    }

    void FieldValidator::validatePubkey(
        ReasonsGroupType &reason,
        const interface::types::PubkeyType &pubkey) const {
      auto opt_reason = shared_model::validation::validatePubkey(pubkey);
      if (opt_reason) {
        reason.second.push_back(std::move(*opt_reason));
      }
    }

    void FieldValidator::validatePeerAddress(
        ReasonsGroupType &reason,
        const interface::types::AddressType &address) const {
      if (not std::regex_match(address, peer_address_regex_)) {
        auto message =
            (boost::format("Wrongly formed peer address, passed value: '%s'. "
                           "Field should have a valid 'host:port' format where "
                           "host is IPv4 or a "
                           "hostname following RFC1035, RFC1123 specifications")
             % address)
                .str();
        reason.second.push_back(std::move(message));
      }
    }

    void FieldValidator::validateRoleId(
        ReasonsGroupType &reason,
        const interface::types::RoleIdType &role_id) const {
      if (not std::regex_match(role_id, role_id_regex_)) {
        auto message = (boost::format("Wrongly formed role_id, passed value: "
                                      "'%s'. Field should match regex '%s'")
                        % role_id % role_id_pattern_)
                           .str();
        reason.second.push_back(std::move(message));
      }
    }

    void FieldValidator::validateAccountName(
        ReasonsGroupType &reason,
        const interface::types::AccountNameType &account_name) const {
      if (not std::regex_match(account_name, account_name_regex_)) {
        auto message =
            (boost::format("Wrongly formed account_name, passed value: '%s'. "
                           "Field should match regex '%s'")
             % account_name % account_name_pattern_)
                .str();
        reason.second.push_back(std::move(message));
      }
    }

    void FieldValidator::validateDomainId(
        ReasonsGroupType &reason,
        const interface::types::DomainIdType &domain_id) const {
      if (not std::regex_match(domain_id, domain_regex_)) {
        auto message = (boost::format("Wrongly formed domain_id, passed value: "
                                      "'%s'. Field should match regex '%s'")
                        % domain_id % domain_pattern_)
                           .str();
        reason.second.push_back(std::move(message));
      }
    }

    void FieldValidator::validateAssetName(
        ReasonsGroupType &reason,
        const interface::types::AssetNameType &asset_name) const {
      if (not std::regex_match(asset_name, asset_name_regex_)) {
        auto message =
            (boost::format("Wrongly formed asset_name, passed value: '%s'. "
                           "Field should match regex '%s'")
             % asset_name % asset_name_pattern_)
                .str();
        reason.second.push_back(std::move(message));
      }
    }

    void FieldValidator::validateAccountDetailKey(
        ReasonsGroupType &reason,
        const interface::types::AccountDetailKeyType &key) const {
      if (not std::regex_match(key, detail_key_regex_)) {
        auto message = (boost::format("Wrongly formed key, passed value: '%s'. "
                                      "Field should match regex '%s'")
                        % key % detail_key_pattern_)
                           .str();
        reason.second.push_back(std::move(message));
      }
    }

    void FieldValidator::validateAccountDetailValue(
        ReasonsGroupType &reason,
        const interface::types::AccountDetailValueType &value) const {
      if (value.size() > value_size) {
        auto message =
            (boost::format("Detail value size should be less or equal '%d'")
             % value_size)
                .str();
        reason.second.push_back(std::move(message));
      }
    }

    void FieldValidator::validatePrecision(
        ReasonsGroupType &reason,
        const interface::types::PrecisionType &precision) const {
      /* The following validation is pointless since PrecisionType is already
       * uint8_t, but it is going to be changed and the validation will become
       * meaningful.
       */
      interface::types::PrecisionType min = std::numeric_limits<uint8_t>::min();
      interface::types::PrecisionType max = std::numeric_limits<uint8_t>::max();
      if (precision < min or precision > max) {
        auto message =
            (boost::format(
                 "Precision value (%d) is out of allowed range [%d; %d]")
             % precision % min % max)
                .str();
        reason.second.push_back(std::move(message));
      }
    }

    void FieldValidator::validateRolePermission(
        ReasonsGroupType &reason,
        const interface::permissions::Role &permission) const {
      if (not isValid(permission)) {
        reason.second.emplace_back("Provided role permission does not exist");
      }
    }

    void FieldValidator::validateGrantablePermission(
        ReasonsGroupType &reason,
        const interface::permissions::Grantable &permission) const {
      if (not isValid(permission)) {
        reason.second.emplace_back(
            "Provided grantable permission does not exist");
      }
    }

    void FieldValidator::validateQuorum(
        ReasonsGroupType &reason,
        const interface::types::QuorumType &quorum) const {
      if (quorum == 0 or quorum > 128) {
        reason.second.emplace_back("Quorum should be within range (0, 128]");
      }
    }

    void FieldValidator::validateCreatorAccountId(
        ReasonsGroupType &reason,
        const interface::types::AccountIdType &account_id) const {
      if (not std::regex_match(account_id, account_id_regex_)) {
        auto message =
            (boost::format("Wrongly formed creator_account_id, passed value: "
                           "'%s'. Field should match regex '%s'")
             % account_id % account_id_pattern_)
                .str();
        reason.second.push_back(std::move(message));
      }
    }

    void FieldValidator::validateCreatedTime(
        ReasonsGroupType &reason,
        interface::types::TimestampType timestamp,
        interface::types::TimestampType now) const {
      if (now + future_gap_ < timestamp) {
        auto message = (boost::format("bad timestamp: sent from future, "
                                      "timestamp: %llu, now: %llu")
                        % timestamp % now)
                           .str();
        reason.second.push_back(std::move(message));
      }

      if (now > kMaxDelay + timestamp) {
        auto message =
            (boost::format("bad timestamp: too old, timestamp: %llu, now: %llu")
             % timestamp % now)
                .str();
        reason.second.push_back(std::move(message));
      }
    }

    void FieldValidator::validateCreatedTime(
        ReasonsGroupType &reason,
        interface::types::TimestampType timestamp) const {
      validateCreatedTime(reason, timestamp, time_provider_());
    }

    void FieldValidator::validateCounter(
        ReasonsGroupType &reason,
        const interface::types::CounterType &counter) const {
      if (counter <= 0) {
        auto message =
            (boost::format("Counter should be > 0, passed value: %d") % counter)
                .str();
        reason.second.push_back(message);
      }
    }

    void FieldValidator::validateSignatures(
        ReasonsGroupType &reason,
        const interface::types::SignatureRangeType &signatures,
        const crypto::Blob &source) const {
      if (boost::empty(signatures)) {
        reason.second.emplace_back("Signatures cannot be empty");
      }
      for (const auto &signature : signatures) {
        const auto &sign = signature.signedData();
        const auto &pkey = signature.publicKey();
        bool is_valid = true;

        if (sign.blob().size() != signature_size) {
          reason.second.push_back(
              (boost::format("Invalid signature: %s") % sign.hex()).str());
          is_valid = false;
        }

        if (pkey.blob().size() != public_key_size) {
          reason.second.push_back(
              (boost::format("Invalid pubkey: %s") % pkey.hex()).str());
          is_valid = false;
        }

        if (is_valid
            && not shared_model::crypto::CryptoVerifier<>::verify(
                   sign, source, pkey)) {
          reason.second.push_back((boost::format("Wrong signature [%s;%s]")
                                   % sign.hex() % pkey.hex())
                                      .str());
        }
      }
    }

    void FieldValidator::validateQueryPayloadMeta(
        ReasonsGroupType &reason,
        const interface::QueryPayloadMeta &meta) const {}

    void FieldValidator::validateDescription(
        shared_model::validation::ReasonsGroupType &reason,
        const shared_model::interface::types::DescriptionType &description)
        const {
      if (description.size() > description_size) {
        reason.second.push_back(
            (boost::format("Description size should be less or equal '%d'")
             % description_size)
                .str());
      }
    }
    void FieldValidator::validateBatchMeta(
        shared_model::validation::ReasonsGroupType &reason,
        const interface::BatchMeta &batch_meta) const {}

    void FieldValidator::validateHeight(
        shared_model::validation::ReasonsGroupType &reason,
        const shared_model::interface::types::HeightType &height) const {
      if (height <= 0) {
        auto message =
            (boost::format("Height should be > 0, passed value: %d") % height)
                .str();
        reason.second.push_back(message);
      }
    }

    void FieldValidator::validateHash(ReasonsGroupType &reason,
                                      const crypto::Hash &hash) const {
      if (hash.size() != hash_size) {
        reason.second.push_back(
            (boost::format("Hash has invalid size: %d") % hash.size()).str());
      }
    }

    boost::optional<ConcreteReasonType> validatePubkey(
        const interface::types::PubkeyType &pubkey) {
      if (pubkey.blob().size() != FieldValidator::public_key_size) {
        return (boost::format("Public key has wrong size, passed size: "
                              "%d. Expected size: %d")
                % pubkey.blob().size() % FieldValidator::public_key_size)
            .str();
      }
      return boost::none;
    }

    void validatePaginationMetaPageSize(ReasonsGroupType &reason,
                                        const size_t &page_size) {
      if (page_size <= 0) {
        reason.second.push_back(
            (boost::format(
                 "Page size is %s (%d), while it must be a non-zero positive.")
             % (page_size == 0 ? "zero" : "negative") % page_size)
                .str());
      }
    }

    void FieldValidator::validateTxPaginationMeta(
        ReasonsGroupType &reason,
        const interface::TxPaginationMeta &tx_pagination_meta) const {
      validatePaginationMetaPageSize(reason, tx_pagination_meta.pageSize());
      const auto first_hash = tx_pagination_meta.firstTxHash();
      if (first_hash) {
        validateHash(reason, *first_hash);
      }
    }

    void FieldValidator::validateAccountAssetPaginationMeta(
        ReasonsGroupType &reason,
        const interface::AccountAssetPaginationMeta
            &account_asset_pagination_meta) const {
      validatePaginationMetaPageSize(reason,
                                     account_asset_pagination_meta.pageSize());
      const auto first_asset_id = account_asset_pagination_meta.firstAssetId();
      if (first_asset_id) {
        validateAssetId(reason, *first_asset_id);
      }
    }

  }  // namespace validation
}  // namespace shared_model
