/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/iroha_conf_loader.hpp"

#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iterator>
#include <limits>
#include <optional>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>

#include <fmt/core.h>
#include <fmt/format.h>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/rapidjson.h>
#include <boost/algorithm/string/join.hpp>
#include <boost/range/adaptor/map.hpp>
#include "common/bind.hpp"
#include "common/files.hpp"
#include "common/result.hpp"
#include "logger/logger.hpp"
#include "main/iroha_conf_literals.hpp"
#include "torii/tls_params.hpp"

/// The length of the string around the error place to print in case of JSON
/// syntax error.
static constexpr size_t kBadJsonPrintLength = 15;

/// The offset of printed chunk towards file start from the error position.
static constexpr size_t kBadJsonPrintOffsset = 5;

static char const *kEnvVarPrefix = "IROHA";

static_assert(kBadJsonPrintOffsset <= kBadJsonPrintLength,
              "The place of error is out of the printed string boundaries!");

using ConstJsonValRef = std::reference_wrapper<rapidjson::Value const>;

using iroha::operator|;

char const *IrohadConfig::Crypto::Default::kName =
    config_members::kCryptoProviderDefault;

class ConfigParsingException : public std::runtime_error {
  using std::runtime_error::runtime_error;
};

std::optional<std::string_view> getOptEnvRaw(
    std::string_view key, std::optional<logger::LoggerPtr> log) {
  char const *val = getenv(key.data());
  if (log) {
    log.value()->trace(
        "lookup ENV({}){}",
        key,
        val ? fmt::format(" = {}", val) : std::string{": not set"});
  }
  if (not val) {
    return std::nullopt;
  }
  return val;
}

/**
 * Throws a runtime exception if the given condition is false.
 * @param condition
 * @param error - error message
 */
inline void assert_fatal(bool condition,
                         std::string_view printable_path,
                         std::string error) {
  if (!condition) {
    throw ConfigParsingException(fmt::format("{}: {}", printable_path, error));
  }
}

inline logger::LogLevel getLogLevel(std::string level_str,
                                    std::string_view printable_path) {
  const auto it = config_members::LogLevels.find(level_str);
  assert_fatal(it != config_members::LogLevels.end(),
               printable_path,
               fmt::format("wrong log level `{}': must be one of `{}'",
                           level_str,
                           fmt::join(config_members::LogLevels
                                         | boost::adaptors::map_keys,
                                     "', `")));
  return it->second;
}

std::string makeEnvDictChildKey(std::string_view base_path,
                                std::string_view child_key) {
  std::string child_key_upper;
  std::transform(child_key.begin(),
                 child_key.end(),
                 std::back_inserter(child_key_upper),
                 ::toupper);
  return base_path.empty() ? child_key_upper
                           : fmt::format("{}_{}", base_path, child_key_upper);
}

template <typename T, typename = decltype(std::to_string(std::declval<T>()))>
std::string makeEnvDictChildKey(std::string_view base_path,
                                T const &child_key) {
  return makeEnvDictChildKey(base_path, std::to_string(child_key));
}

/**
 * A class for reading a structure from a JSON node.
 */
class JsonDeserializerImpl {
 public:
  JsonDeserializerImpl(
      std::shared_ptr<shared_model::interface::CommonObjectsFactory>
          common_objects_factory,
      std::optional<ConstJsonValRef> json,
      std::optional<logger::LoggerPtr> log)
      : common_objects_factory_(std::move(common_objects_factory)),
        env_path_(kEnvVarPrefix),
        json_(json),
        printable_path_(""),
        log_(std::move(log)) {}

  /**
   * Load the data from rapidjson::Value. Checks the JSON type and throws
   * exception if it is wrong.
   * @tparam TDest - the type of data to read from JSON
   * @param src - the source JSON to read the data from
   * @param path - path in the configuration structure
   * @return the deserialized data
   */
  template <typename TDest>
  TDest deserialize() {
    TDest dest;
    assert_fatal(loadInto(dest), "deserialization failed");
    return dest;
  }

 private:
  JsonDeserializerImpl(
      std::shared_ptr<shared_model::interface::CommonObjectsFactory>
          common_objects_factory,
      std::optional<std::string> env_path,
      std::optional<ConstJsonValRef> json,
      std::string printable_path,
      std::optional<logger::LoggerPtr> log)
      : common_objects_factory_(std::move(common_objects_factory)),
        env_path_(std::move(env_path)),
        json_(json),
        printable_path_(std::move(printable_path)),
        log_(std::move(log)) {}

  JsonDeserializerImpl getDictChild(std::string const &key) {
    return JsonDeserializerImpl{
        common_objects_factory_,
        env_path_ ? std::make_optional(makeEnvDictChildKey(key)) : std::nullopt,
        json_ | [&](auto const &json) -> std::optional<ConstJsonValRef> {
          assert_fatal(json_->get().IsObject(), "must be a JSON object.");
          auto const json_obj = json_->get().GetObject();
          const auto it = json_obj.FindMember(key);
          if (it != json_obj.MemberEnd()) {
            return it->value;
          }
          return std::nullopt;
        },
        makePrintableDictChildKey(key),
        log_};
  }

  template <typename T>
  std::string makePrintableDictChildKey(T const &child_key) {
    return fmt::format("{}/{}", printable_path_, child_key);
  }

  template <typename T>
  std::string makeEnvDictChildKey(T const &child_key) {
    assert(env_path_);
    return ::makeEnvDictChildKey(env_path_.value(), child_key);
  }

  template <typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
  std::string makePrintableArrayElemPath(T const &index) {
    return fmt::format("{}[{}]", printable_path_, index);
  }

  template <typename F>
  bool iterateDictChildren(F f) {
    if (json_) {
      assert_fatal(json_->get().IsObject(), "must be a JSON object.");
      auto const json_obj = json_->get().GetObject();
      for (const auto &child_json : json_obj) {
        auto const key = child_json.name.GetString();
        f(key,
          JsonDeserializerImpl{common_objects_factory_,
                               std::nullopt,
                               child_json.value,
                               makePrintableDictChildKey(key),
                               log_});
      }
      return true;
    }
    if (env_path_) {
      bool have_dict = false;
      for (int i = 0;; ++i) {
        auto array_el_env_val_prefix = makeEnvDictChildKey(i);
        auto array_el_env_key_key =
            fmt::format("{}_KEY", array_el_env_val_prefix);
        auto array_el_env_key_val = ::getOptEnvRaw(array_el_env_key_key, log_);
        if (not array_el_env_key_val) {
          break;
        }
        have_dict = true;
        f(array_el_env_key_val.value(),
          JsonDeserializerImpl{
              common_objects_factory_,
              array_el_env_val_prefix,
              std::nullopt,
              makePrintableDictChildKey(array_el_env_key_val.value()),
              log_});
      }
      return have_dict;
    }
    return false;
  }

  /**
   * Throws a runtime exception if the given condition is false.
   * @param condition
   * @param error - error message
   */
  inline void assert_fatal(bool condition, std::string error) {
    ::assert_fatal(condition, printable_path_, error);
  }

  // ------------ loadInto(path, dst, src) ------------
  // loadInto is a set of functions that load the value from rapidjson::Value to
  // a given destination variable. They check the JSON type and throw exception
  // if it is wrong. The path argument is used to denote the possible error
  // place and parse environment variables.

  template <typename T>
  static constexpr bool IsIntegerLike =
      std::numeric_limits<T>::is_integer or std::is_enum<T>::value;

  template <typename T>
  static constexpr bool IsInt64Like =
      IsIntegerLike<T> and sizeof(T) == sizeof(int64_t);

  template <typename T>
  static constexpr bool fitsType(int64_t i) {
    return static_cast<int64_t>(std::numeric_limits<T>::min()) <= i
        and i <= static_cast<int64_t>(std::numeric_limits<T>::max());
  }

  std::optional<std::string> getOptEnvRaw() const {
    return env_path_ | [this](auto const &env_path) {
      return ::getOptEnvRaw(env_path.c_str(), log_) | [](std::string_view val) {
        return std::make_optional(std::string{val});
      };
    };
  }

  template <typename TDest>
  typename std::enable_if_t<IsInt64Like<TDest> and not std::is_signed_v<TDest>,
                            bool>
  loadInto(TDest &dest) {
    if (json_) {
      assert_fatal(json_->get().IsUint64(), "must be an unsigned integer");
      dest = json_->get().GetUint64();
      return true;
    }
    if (auto from_env = getOptEnvRaw()) {
      dest = std::strtoull(from_env->data(), nullptr, 10);
      return true;
    }
    return false;
  }

  template <typename TDest>
  typename std::enable_if_t<IsInt64Like<TDest> and std::is_signed_v<TDest>,
                            bool>
  loadInto(TDest &dest) {
    if (json_) {
      assert_fatal(json_->get().IsInt64(), "must be a signed integer");
      dest = json_->get().GetInt64();
      return true;
    }
    if (auto from_env = getOptEnvRaw()) {
      dest = std::strtoull(from_env->data(), nullptr, 10);
      return true;
    }
    return false;
  }

  template <typename T, bool is_enum = std::is_enum_v<T>>
  struct BaseTypeHelper {
    using type = T;
  };

  template <typename T>
  struct BaseTypeHelper<T, true> {
    using type = std::underlying_type_t<T>;
  };

  template <typename TDest>
  typename std::enable_if_t<
      IsIntegerLike<TDest> and sizeof(TDest) < sizeof(int64_t),
      bool>
  loadInto(TDest &dest) {
    using TBase = typename BaseTypeHelper<TDest>::type;
    static_assert(fitsType<int64_t>(std::numeric_limits<TBase>::min())
                      and fitsType<int64_t>(std::numeric_limits<TBase>::max()),
                  "destination type does not fit int64_t");
    int64_t val;
    if (json_) {
      assert_fatal(json_->get().IsInt64(), "must be an integer");
      val = json_->get().GetInt64();
    } else if (auto from_env = getOptEnvRaw()) {
      val = std::strtoull(from_env->data(), nullptr, 10);
    } else {
      return false;
    }
    assert_fatal(fitsType<TDest>(val), "integer value out of range");
    reinterpret_cast<TBase &>(dest) = val;
    return true;
  }

  template <typename T>
  bool loadInto(std::shared_ptr<T> &dest) {
    std::unique_ptr<T> uniq_dest;
    if (not loadInto<std::unique_ptr<T>>(uniq_dest)) {
      return false;
    }
    dest = std::move(uniq_dest);
    return true;
  }

  template <typename Elem>
  bool loadInto(std::vector<Elem> &dest) {
    auto load_elem = [&dest](JsonDeserializerImpl node) {
      Elem el;
      if (node.loadInto<Elem>(el)) {
        dest.emplace_back(std::move(el));
        return true;
      }
      return false;
    };

    if (json_) {
      assert_fatal(json_->get().IsArray(), "must be an array.");
      const auto arr = json_->get().GetArray();
      for (size_t i = 0; i < arr.Size(); ++i) {
        load_elem(JsonDeserializerImpl{common_objects_factory_,
                                       std::nullopt,
                                       arr[i],
                                       makePrintableArrayElemPath(i),
                                       log_});
      }
      return true;  // empty vector in JSON is loaded
    }
    if (env_path_) {
      for (int i = 0;; ++i) {
        auto array_el_env_key_prefix = makeEnvDictChildKey(i);
        if (not load_elem(JsonDeserializerImpl{common_objects_factory_,
                                               array_el_env_key_prefix,
                                               std::nullopt,
                                               makePrintableArrayElemPath(i),
                                               log_})) {
          break;
        }
      }
    }
    return not dest.empty();
  }

  template <typename Key, typename Val>
  bool loadInto(std::unordered_map<Key, Val> &dest) {
    return iterateDictChildren(
        [&](std::string_view key, JsonDeserializerImpl val_raw) {
          dest.emplace(key, val_raw.deserialize<Val>());
        });
  }

  template <typename T>
  inline bool loadInto(std::optional<T> &dest) {
    T val;
    if (loadInto(val)) {
      dest = std::move(val);
    }
    return true;
  }

  template <typename T>
  inline bool loadInto(boost::optional<T> &dest) {
    T val;
    if (loadInto(val)) {
      dest = std::move(val);
    }
    return true;
  }

  // This is the fallback template function specialization that is overriden by
  // multiple partial specializations below.
  template <typename TDest>
  typename std::enable_if_t<not IsIntegerLike<TDest>, bool> loadInto(TDest &) {
    BOOST_THROW_EXCEPTION(
        ConfigParsingException("Wrong type. Should never reach here."));
    return false;
  }

  // ------------ end of loadInto(path, dst, src) ------------

  /**
   * Adds the children logger configs from parent logger JSON object to parent
   * logger config. The parent logger JSON object is searched for the children
   * config section, and the children configs are parsed and created if the
   * section is present.
   * @param parent_config - the parent logger config
   */
  bool addChildrenLoggerConfigs(logger::LoggerManagerTree &parent_config);

  /**
   * Overrides the logger configuration with the values from JSON object.
   * @param cfg - the configuration to use as base
   */
  void updateLoggerConfig(logger::LoggerConfig &cfg);

  /**
   * Gets an optional value by a key from a JSON object.
   * @param key - the key for the requested value
   * @return the value if present in the JSON object, otherwise boost::none.
   */
  template <typename TDest, typename TKey>
  boost::optional<TDest> getOptValByKey(const TKey &key) {
    TDest val;
    return boost::make_optional(getDictChild(key).loadInto(val), val);
  }

  std::shared_ptr<shared_model::interface::CommonObjectsFactory>
      common_objects_factory_;
  std::optional<std::string> env_path_;
  std::optional<ConstJsonValRef> json_;
  std::string printable_path_;
  std::optional<logger::LoggerPtr> log_;
};

// ------------ loadInto(path, dst, src) specializations ------------

template <>
inline bool JsonDeserializerImpl::loadInto(std::string &dest) {
  if (json_) {
    assert_fatal(json_->get().IsString(), "must be a string");
    dest = json_->get().GetString();
    return true;
  } else if (auto from_env = getOptEnvRaw()) {
    dest = std::move(from_env).value();
    return true;
  }
  return false;
}

template <>
inline bool JsonDeserializerImpl::loadInto(logger::LogLevel &dest) {
  std::string level_str;
  if (not loadInto(level_str)) {
    return false;
  }
  dest = getLogLevel(level_str, printable_path_);
  return true;
}

template <>
inline bool JsonDeserializerImpl::loadInto(logger::LogPatterns &dest) {
  return iterateDictChildren(
      [&](std::string_view level, JsonDeserializerImpl pattern_raw) {
        std::string pattern_str;
        pattern_raw.loadInto(pattern_str);
        dest.setPattern(getLogLevel(std::string{level}, printable_path_),
                        pattern_str);
      });
}

template <>
inline bool JsonDeserializerImpl::loadInto(bool &dest) {
  if (json_) {
    assert_fatal(json_->get().IsBool(), "must be a boolean");
    dest = json_->get().GetBool();
    return true;
  } else if (auto from_env = getOptEnvRaw()) {
    static std::vector<std::string_view> kTextFalse{"false", "f", "0"};
    static std::vector<std::string_view> kTextTrue{"true", "t", "1"};
    std::string from_env_lower;
    std::transform(from_env->begin(),
                   from_env->end(),
                   std::back_inserter(from_env_lower),
                   ::tolower);
    auto has_elem = [](auto const &collection, auto const &elem) {
      return std::find(collection.begin(), collection.end(), elem)
          != collection.end();
    };
    if (has_elem(kTextFalse, from_env_lower)) {
      dest = false;
      return true;
    }
    if (has_elem(kTextTrue, from_env_lower)) {
      dest = true;
      return true;
    }
    return false;
  }
  return false;
}

template <>
inline bool JsonDeserializerImpl::loadInto(
    std::unique_ptr<logger::LoggerManagerTree> &dest) {
  logger::LoggerConfig root_config{logger::kDefaultLogLevel,
                                   logger::LogPatterns{}};
  updateLoggerConfig(root_config);
  dest = std::make_unique<logger::LoggerManagerTree>(
      std::make_shared<const logger::LoggerConfig>(std::move(root_config)));
  addChildrenLoggerConfigs(*dest);
  return true;
}

template <>
inline bool
JsonDeserializerImpl::loadInto<std::shared_ptr<shared_model::interface::Peer>>(
    std::shared_ptr<shared_model::interface::Peer> &dest) {
  std::string address;
  std::string public_key_str;
  if (not getDictChild(config_members::Address).loadInto(address)
      or not getDictChild(config_members::PublicKey).loadInto(public_key_str)) {
    return false;
  }
  auto tls_certificate_path =
      getOptValByKey<std::string>(config_members::TlsCertificatePath);

  std::optional<std::string> tls_certificate_str;
  if (tls_certificate_path) {
    iroha::readTextFile(*tls_certificate_path)
        .match([&tls_certificate_str](
                   const auto &v) { tls_certificate_str = v.value; },
               [&](const auto &e) {
                 throw ConfigParsingException{
                     fmt::format("Error reading file specified in {}: {}",
                                 printable_path_,
                                 e.error)};
               });
  }

  common_objects_factory_
      ->createPeer(address,
                   shared_model::interface::types::PublicKeyHexStringView{
                       public_key_str},
                   tls_certificate_str)
      .match([&dest](auto &&v) { dest = std::move(v.value); },
             [&](const auto &error) {
               throw ConfigParsingException(
                   fmt::format("Failed to create a peer at {}: {}",
                               printable_path_,
                               error.error));
             });

  return true;
}

template <>
inline bool JsonDeserializerImpl::loadInto(iroha::torii::TlsParams &dest) {
  return getDictChild(config_members::Port).loadInto(dest.port)
      and getDictChild(config_members::KeyPairPath).loadInto(dest.key_path);
}

template <>
inline bool JsonDeserializerImpl::loadInto(
    IrohadConfig::InterPeerTls::PeerCertProvider &dest) {
  std::string type;
  if (not getDictChild(config_members::Type).loadInto(type)) {
    return false;
  }
  if (type == config_members::RootCert) {
    IrohadConfig::InterPeerTls::RootCert root_cert;
    if (not getDictChild(config_members::Path).loadInto(root_cert.path)) {
      return false;
    }
    dest = std::move(root_cert);
  } else if (type == config_members::InLengerCerts) {
    dest = IrohadConfig::InterPeerTls::FromWsv{};
  } else {
    throw ConfigParsingException{std::string{
        "Unimplemented peer certificate provider type: '" + type + "'"}};
  }
  return true;
}

template <>
inline bool JsonDeserializerImpl::loadInto(IrohadConfig::InterPeerTls &dest) {
  return getDictChild(config_members::KeyPairPath)
             .loadInto(dest.my_tls_creds_path)
      and getDictChild(config_members::PeerCertProvider)
              .loadInto(dest.peer_certificates);
}

template <>
inline bool JsonDeserializerImpl::loadInto(IrohadConfig::DbConfig &dest) {
  if (getDictChild(config_members::DbType).loadInto(dest.type)) {
    if (dest.type == kDbTypeRocksdb) {
      return getDictChild(config_members::DbPath).loadInto(dest.path);
    } else if (dest.type == kDbTypePostgres) {
      return getDictChild(config_members::Host).loadInto(dest.host)
          and getDictChild(config_members::Port).loadInto(dest.port)
          and getDictChild(config_members::User).loadInto(dest.user)
          and getDictChild(config_members::Password).loadInto(dest.password)
          and getDictChild(config_members::WorkingDbName)
                  .loadInto(dest.working_dbname)
          and getDictChild(config_members::MaintenanceDbName)
                  .loadInto(dest.maintenance_dbname);
    }
  }
  return false;
}

template <>
inline bool JsonDeserializerImpl::loadInto(IrohadConfig::UtilityService &dest) {
  return getDictChild(config_members::Ip).loadInto(dest.ip)
      and getDictChild(config_members::Port).loadInto(dest.port);
}

template <>
inline bool JsonDeserializerImpl::loadInto(iroha::multihash::Type &dest) {
  std::string type_str;
  if (not loadInto(type_str)) {
    return false;
  }
  static std::map<std::string_view, iroha::multihash::Type> const
      kNameToMultihash{
          {"ed25519_sha2_256", iroha::multihash::Type::ed25519pub},
          {"ed25519_sha3_256", iroha::multihash::Type::ed25519_sha3_256},
      };
  auto const it = kNameToMultihash.find(type_str);
  assert_fatal(
      it != kNameToMultihash.end(),
      fmt::format(
          "wrong multihash type `{}': must be one of `{}'",
          type_str,
          fmt::join(kNameToMultihash | boost::adaptors::map_keys, "', `")));
  dest = it->second;
  return true;
}

template <>
inline bool JsonDeserializerImpl::loadInto(
    IrohadConfig::Crypto::Default &dest) {
  if (not getDictChild(config_members::kCryptoType).loadInto(dest.type)
      or not getDictChild(config_members::PrivateKey)
                 .loadInto(dest.private_key)) {
    return false;
  }
  assert_fatal(getDictChild(config_members::Type).deserialize<std::string>()
                   == IrohadConfig::Crypto::Default::kName,
               fmt::format("only `{}' crypto provider type is supported now",
                           IrohadConfig::Crypto::Default::kName));
  return true;
}

template <>
inline bool JsonDeserializerImpl::loadInto(IrohadConfig::Crypto &dest) {
  return getDictChild(config_members::kProviders).loadInto(dest.providers)
      and getDictChild(config_members::kSigner).loadInto(dest.signer);
}

uint32_t IrohadConfig::getMaxpProposalPack() const {
  return max_proposal_pack.value_or(10);
}

template <>
inline bool JsonDeserializerImpl::loadInto(IrohadConfig &dest) {
  using namespace config_members;
  return getDictChild(BlockStorePath).loadInto(dest.block_store_path)
      and getDictChild(ToriiPort).loadInto(dest.torii_port)
      and getDictChild(ToriiTlsParams).loadInto(dest.torii_tls_params)
      and getDictChild(InterPeerTls).loadInto(dest.inter_peer_tls)
      and getDictChild(InternalPort).loadInto(dest.internal_port)
      and getDictChild(DbConfig).loadInto(dest.database_config)
      and (dest.database_config or getDictChild(PgOpt).loadInto(dest.pg_opt))
      and getDictChild(MaxProposalSize).loadInto(dest.max_proposal_size)
      and getDictChild(ProposalCreationTimeout)
              .loadInto(dest.proposal_creation_timeout)
      and getDictChild(MaxProposalPack).loadInto(dest.max_proposal_pack)
      and getDictChild(HealthcheckPort).loadInto(dest.healthcheck_port)
      and getDictChild(MaxPastCreatedHours).loadInto(dest.max_past_created_hours)
      and getDictChild(VoteDelay).loadInto(dest.vote_delay)
      and getDictChild(MstSupport).loadInto(dest.mst_support)
      and getDictChild(MstExpirationTime).loadInto(dest.mst_expiration_time)
      and getDictChild(MaxRoundsDelay).loadInto(dest.max_round_delay_ms)
      and getDictChild(StaleStreamMaxRounds)
              .loadInto(dest.stale_stream_max_rounds)
      and getDictChild(LogSection).loadInto(dest.logger_manager)
      and getDictChild(InitialPeers).loadInto(dest.initial_peers)
      and getDictChild(UtilityService).loadInto(dest.utility_service)
      and getDictChild(kCrypto).loadInto(dest.crypto)
      and (getDictChild("metrics").loadInto(dest.metrics_addr_port) or true);
}

// ------------ end of loadInto(path, dst, src) specializations ------------

/**
 * Adds the children logger configs from parent logger JSON object to parent
 * logger config. The parent logger JSON object is searched for the children
 * config section, and the children configs are parsed and created if the
 * section is present.
 * @param parent_config - the parent logger config
 */
bool JsonDeserializerImpl::addChildrenLoggerConfigs(
    logger::LoggerManagerTree &parent_config) {
  return getDictChild(config_members::LogChildrenSection)
      .iterateDictChildren([&](std::string_view child_name,
                               JsonDeserializerImpl child_conf_raw) {
        auto child_conf = parent_config.registerChild(
            std::string{child_name},
            child_conf_raw.getOptValByKey<logger::LogLevel>(
                config_members::LogLevel),
            child_conf_raw.getOptValByKey<logger::LogPatterns>(
                config_members::LogPatternsSection));
        child_conf_raw.addChildrenLoggerConfigs(*child_conf);
      });
}

/**
 * Overrides the logger configuration with the values from JSON object.
 * @param cfg - the configuration to use as base
 */
void JsonDeserializerImpl::updateLoggerConfig(logger::LoggerConfig &cfg) {
  getDictChild(config_members::LogLevel).loadInto(cfg.log_level);
  getDictChild(config_members::LogPatternsSection).loadInto(cfg.patterns);
}

void reportJsonParsingError(const rapidjson::Document &doc,
                            const std::string &text) {
  if (doc.HasParseError()) {
    const size_t error_offset = doc.GetErrorOffset();
    // This ensures the unsigned string beginning position does not cross zero:
    const size_t print_offset =
        std::max(error_offset, kBadJsonPrintOffsset) - kBadJsonPrintOffsset;
    std::string json_error_buf = text.substr(print_offset, kBadJsonPrintLength);
    throw ConfigParsingException{fmt::format(
        "JSON parse error (near `{}'): {}",
        json_error_buf,
        std::string(rapidjson::GetParseError_En(doc.GetParseError())))};
  }
}

// TODO mboldyrev 2019.05.06 IR-465 make config loader testable
iroha::expected::Result<IrohadConfig, std::string> parse_iroha_config(
    const std::string &conf_path,
    std::shared_ptr<shared_model::interface::CommonObjectsFactory>
        common_objects_factory,
    std::optional<logger::LoggerPtr> log) {
  std::optional<std::string> config_text;
  if (not conf_path.empty()) {
    auto config_text_result = iroha::readTextFile(conf_path);
    if (auto e = iroha::expected::resultToOptionalError(config_text_result)) {
      return std::move(e).value();
    }
    config_text = std::move(config_text_result).assumeValue();
  }

  try {
    auto doc{config_text | [](std::string const &text)
                 -> std::optional<rapidjson::Document const> {
      rapidjson::Document doc;
      doc.Parse(text.data(), text.size());
      reportJsonParsingError(doc, text);
      return std::make_optional(std::move(doc));
    }};

    JsonDeserializerImpl parser(common_objects_factory, doc, std::move(log));
    return parser.deserialize<IrohadConfig>();
  } catch (ConfigParsingException const &e) {
    return e.what();
  };
}

uint32_t IrohadConfig::getProposalDelay() const {
  return getProposalCreationTimeout() * 2ul;
}

uint32_t IrohadConfig::getProposalCreationTimeout() const {
  return proposal_creation_timeout.value_or(3000ul);
}
