/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/iroha_conf_loader.hpp"

#include <fstream>
#include <limits>
#include <sstream>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/rapidjson.h>
#include <boost/algorithm/string/join.hpp>
#include <boost/range/adaptor/map.hpp>
#include "common/files.hpp"
#include "common/result.hpp"
#include "cryptography/public_key.hpp"
#include "main/iroha_conf_literals.hpp"
#include "torii/tls_params.hpp"

/// The length of the string around the error place to print in case of JSON
/// syntax error.
static constexpr size_t kBadJsonPrintLength = 15;

/// The offset of printed chunk towards file start from the error position.
static constexpr size_t kBadJsonPrintOffsset = 5;

static_assert(kBadJsonPrintOffsset <= kBadJsonPrintLength,
              "The place of error is out of the printed string boundaries!");

class JsonDeserializerException : public std::runtime_error {
  using std::runtime_error::runtime_error;
};

/**
 * A class for reading a structure from a JSON node.
 */
class JsonDeserializerImpl {
 public:
  JsonDeserializerImpl(
      std::shared_ptr<shared_model::interface::CommonObjectsFactory>
          common_objects_factory)
      : common_objects_factory_(std::move(common_objects_factory)) {}

  /**
   * Load the data from rapidjson::Value. Checks the JSON type and throws
   * exception if it is wrong.
   * @tparam TDest - the type of data to read from JSON
   * @param src - the source JSON to read the data from
   * @param path - optional path that is used to denote the possible error
   * place.
   * @return the deserialized data
   */
  template <typename TDest>
  TDest deserialize(const rapidjson::Value &src,
                    boost::optional<std::string> path = boost::none) {
    TDest dest;
    getVal(path.value_or(""), dest, src);
    return dest;
  }

 private:
  // ------------ getVal(path, dst, src) ------------
  // getVal is a set of functions that load the value from rapidjson::Value to
  // a given destination variable. They check the JSON type and throw exception
  // if it is wrong. The path argument is used to denote the possible error
  // place.

  template <typename T>
  static constexpr bool IsIntegerLike =
      std::numeric_limits<T>::is_integer or std::is_enum<T>::value;

  template <typename TDest>
  typename std::enable_if<IsIntegerLike<TDest>>::type getVal(
      const std::string &path, TDest &dest, const rapidjson::Value &src) {
    assert_fatal(src.IsInt64(), path + " must be an integer");
    const int64_t val = src.GetInt64();
    assert_fatal(val >= std::numeric_limits<TDest>::min()
                     && val <= std::numeric_limits<TDest>::max(),
                 path + ": integer value out of range");
    dest = val;
  }

  template <typename Elem>
  void getVal(const std::string &path,
              std::vector<Elem> &dest,
              const rapidjson::Value &src) {
    assert_fatal(src.IsArray(), path + " must be an array.");
    const auto arr = src.GetArray();
    for (size_t i = 0; i < arr.Size(); ++i) {
      Elem el;
      getVal(sublevelPath(path, std::to_string(i)), el, arr[i]);
      dest.emplace_back(std::move(el));
    }
  }

  template <typename T>
  void getVal(const std::string &path,
              std::shared_ptr<T> &dest,
              const rapidjson::Value &src) {
    std::unique_ptr<T> uniq_dest;
    getVal<std::unique_ptr<T>>(path, uniq_dest, src);
    dest = std::move(uniq_dest);
  }

  // This is the fallback template function specialization that is overriden by
  // multiple partial specializations below.
  template <typename TDest>
  typename std::enable_if<not IsIntegerLike<TDest>>::type getVal(
      const std::string &path, TDest &, const rapidjson::Value &) {
    BOOST_THROW_EXCEPTION(
        std::runtime_error("Wrong type. Should never reach here."));
  }

  // ------------ end of getVal(path, dst, src) ------------

  /**
   * Adds the children logger configs from parent logger JSON object to parent
   * logger config. The parent logger JSON object is searched for the children
   * config section, and the children configs are parsed and created if the
   * section is present.
   * @param path - current config node path used to denote the possible error
   *    place.
   * @param parent_config - the parent logger config
   * @param parent_obj - the parent logger json configuration
   */
  void addChildrenLoggerConfigs(
      const std::string &path,
      logger::LoggerManagerTree &parent_config,
      const rapidjson::Value::ConstObject &parent_obj) {
    const auto it = parent_obj.FindMember(config_members::LogChildrenSection);
    if (it != parent_obj.MemberEnd()) {
      auto children_section_path =
          sublevelPath(path, config_members::LogChildrenSection);
      for (const auto &child_json : it->value.GetObject()) {
        assert_fatal(child_json.name.IsString(),
                     "Child logger key must be a string holding its tag.");
        assert_fatal(child_json.value.IsObject(),
                     "Child logger value must be a JSON object.");
        auto child_tag = child_json.name.GetString();
        const auto child_obj = child_json.value.GetObject();
        auto child_path = sublevelPath(children_section_path, child_tag);
        auto child_conf = parent_config.registerChild(
            std::move(child_tag),
            getOptValByKey<logger::LogLevel>(
                child_path, child_obj, config_members::LogLevel),
            getOptValByKey<logger::LogPatterns>(
                child_path, child_obj, config_members::LogPatternsSection));
        addChildrenLoggerConfigs(std::move(child_path), *child_conf, child_obj);
      }
    }
  }

  /**
   * Overrides the logger configuration with the values from JSON object.
   * @param path - current config node path used to denote the possible error
   *    place.
   * @param cfg - the configuration to use as base
   * @param obj - the JSON object to take overrides from
   */
  void updateLoggerConfig(const std::string &path,
                          logger::LoggerConfig &cfg,
                          const rapidjson::Value::ConstObject &obj) {
    tryGetValByKey(path, cfg.log_level, obj, config_members::LogLevel);
    tryGetValByKey(path, cfg.patterns, obj, config_members::LogPatternsSection);
  }

  /**
   * Gets a value by a key from a JSON object, if present.
   * @param path - current config node path used to denote the possible error
   *    place.
   * @param dest - the variable to store the value
   * @param obj - the source JSON object
   * @param key - the key for the requested value
   * @return true if the value was loaded, otherwise false.
   */
  template <typename TDest, typename TKey>
  bool tryGetValByKey(const std::string &path,
                      TDest &dest,
                      const rapidjson::Value::ConstObject &obj,
                      const TKey &key) {
    const auto it = obj.FindMember(key);
    if (it == obj.MemberEnd()) {
      return false;
    } else {
      getVal(sublevelPath(path, key), dest, it->value);
      return true;
    }
  }

  /// A variant of tryGetValByKey for optional destination
  template <typename TDest, typename TKey>
  bool tryGetValByKey(const std::string &path,
                      boost::optional<TDest> &dest,
                      const rapidjson::Value::ConstObject &obj,
                      const TKey &key) {
    dest = getOptValByKey<TDest>(path, obj, key);
    return true;  // value loaded any way, either from file or boost::none
  }

  /**
   * Gets an optional value by a key from a JSON object.
   * @param path - current config node path used to denote the possible error
   *    place.
   * @param obj - the source JSON object
   * @param key - the key for the requested value
   * @return the value if present in the JSON object, otherwise boost::none.
   */
  template <typename TDest, typename TKey>
  boost::optional<TDest> getOptValByKey(
      const std::string &path,
      const rapidjson::Value::ConstObject &obj,
      const TKey &key) {
    TDest val;
    return boost::make_optional(tryGetValByKey(path, val, obj, key), val);
  }

  /**
   * Gets a value by a key from a JSON object. Throws an exception if the value
   * was not loaded.
   * @param path - current config node path used to denote the possible error
   *    place.
   * @param dest - the variable to store the value
   * @param obj - the source JSON object
   * @param key - the key for the requested value
   */
  template <typename TDest, typename TKey>
  void getValByKey(const std::string &path,
                   TDest &dest,
                   const rapidjson::Value::ConstObject &obj,
                   const TKey &key) {
    assert_fatal(tryGetValByKey(path, dest, obj, key),
                 path + " has no key '" + key + "'.");
  }

  /**
   * Adds one sublevel to the path denoting a place in config tree.
   * @param parent - the location of the sublevel
   * @param child - the name of sublevel
   * @return the path to the sublevel
   */
  template <typename TChild>
  inline std::string sublevelPath(std::string parent, TChild child) {
    std::stringstream child_sstream;
    child_sstream << child;
    return std::move(parent) + "/" + child_sstream.str();
  }

  /**
   * Throws a runtime exception if the given condition is false.
   * @param condition
   * @param error - error message
   */
  inline void assert_fatal(bool condition, std::string error) {
    if (!condition) {
      throw JsonDeserializerException(error);
    }
  }

  std::shared_ptr<shared_model::interface::CommonObjectsFactory>
      common_objects_factory_;
};

// ------------ getVal(path, dst, src) specializations ------------

template <>
inline void JsonDeserializerImpl::getVal<bool>(const std::string &path,
                                               bool &dest,
                                               const rapidjson::Value &src) {
  assert_fatal(src.IsBool(), path + " must be a boolean");
  dest = src.GetBool();
}

template <>
inline void JsonDeserializerImpl::getVal<std::string>(
    const std::string &path, std::string &dest, const rapidjson::Value &src) {
  assert_fatal(src.IsString(), path + " must be a string");
  dest = src.GetString();
}

template <>
inline void JsonDeserializerImpl::getVal<logger::LogLevel>(
    const std::string &path,
    logger::LogLevel &dest,
    const rapidjson::Value &src) {
  std::string level_str;
  getVal(path, level_str, src);
  const auto it = config_members::LogLevels.find(level_str);
  if (it == config_members::LogLevels.end()) {
    BOOST_THROW_EXCEPTION(std::runtime_error(
        "Wrong log level at " + path + ": must be one of '"
        + boost::algorithm::join(
              config_members::LogLevels | boost::adaptors::map_keys, "', '")
        + "'."));
  }
  dest = it->second;
}

template <>
inline void JsonDeserializerImpl::getVal<logger::LogPatterns>(
    const std::string &path,
    logger::LogPatterns &dest,
    const rapidjson::Value &src) {
  assert_fatal(src.IsObject(),
               path + " must be a map from log level to pattern");
  for (const auto &pattern_entry : src.GetObject()) {
    logger::LogLevel level;
    std::string pattern_str;
    getVal(sublevelPath(path, "(level name)"), level, pattern_entry.name);
    getVal(sublevelPath(path, "(pattern)"), pattern_str, pattern_entry.value);
    dest.setPattern(level, pattern_str);
  }
}

template <>
inline void
JsonDeserializerImpl::getVal<std::unique_ptr<logger::LoggerManagerTree>>(
    const std::string &path,
    std::unique_ptr<logger::LoggerManagerTree> &dest,
    const rapidjson::Value &src) {
  assert_fatal(src.IsObject(), path + " must be a logger tree config");
  logger::LoggerConfig root_config{logger::kDefaultLogLevel,
                                   logger::LogPatterns{}};
  updateLoggerConfig(path, root_config, src.GetObject());
  dest = std::make_unique<logger::LoggerManagerTree>(
      std::make_shared<const logger::LoggerConfig>(std::move(root_config)));
  addChildrenLoggerConfigs(path, *dest, src.GetObject());
}

template <>
inline void
JsonDeserializerImpl::getVal<std::unique_ptr<shared_model::interface::Peer>>(
    const std::string &path,
    std::unique_ptr<shared_model::interface::Peer> &dest,
    const rapidjson::Value &src) {
  assert_fatal(src.IsObject(), path + " must be a dictionary");
  const auto obj = src.GetObject();
  std::string address;
  getValByKey(path, address, obj, config_members::Address);
  std::string public_key_str;
  getValByKey(path, public_key_str, obj, config_members::PublicKey);
  boost::optional<std::string> tls_certificate_path =
      getOptValByKey<std::string>(
          path, obj, config_members::TlsCertificatePath);

  boost::optional<std::string> tls_certificate_str;
  if (tls_certificate_path) {
    iroha::readTextFile(*tls_certificate_path)
        .match([&tls_certificate_str](
                   const auto &v) { tls_certificate_str = v.value; },
               [this, &path](const auto &e) {
                 this->assert_fatal(false,
                                    "Error reading file specified in " + path
                                        + ": " + e.error);
               });
  }

  common_objects_factory_
      ->createPeer(
          address,
          shared_model::crypto::PublicKey(
              shared_model::crypto::Blob::fromHexString(public_key_str)),
          tls_certificate_str)
      .match([&dest](auto &&v) { dest = std::move(v.value); },
             [&path](const auto &error) {
               throw JsonDeserializerException("Failed to create a peer at '"
                                               + path + "': " + error.error);
             });
}

template <>
inline void JsonDeserializerImpl::getVal<iroha::torii::TlsParams>(
    const std::string &path,
    iroha::torii::TlsParams &dest,
    const rapidjson::Value &src) {
  assert_fatal(src.IsObject(), path + " must be a dictionary");
  const auto obj = src.GetObject();
  getValByKey(path, dest.port, obj, config_members::Port);
  getValByKey(path, dest.key_path, obj, config_members::KeyPairPath);
}

template <>
inline void JsonDeserializerImpl::getVal<IrohadConfig::InterPeerTls>(
    const std::string &path,
    IrohadConfig::InterPeerTls &dest,
    const rapidjson::Value &src) {
  assert_fatal(src.IsObject(), path + " must be a dictionary");
  const auto obj = src.GetObject();
  getValByKey(path, dest.my_tls_creds_path, obj, config_members::KeyPairPath);
  getValByKey(
      path, dest.peer_certificates, obj, config_members::PeerCertProvider);
}

template <>
inline void
JsonDeserializerImpl::getVal<IrohadConfig::InterPeerTls::PeerCertProvider>(
    const std::string &path,
    IrohadConfig::InterPeerTls::PeerCertProvider &dest,
    const rapidjson::Value &src) {
  assert_fatal(src.IsObject(), path + " must be a dictionary");
  const auto obj = src.GetObject();
  std::string type;
  getValByKey(path, type, obj, config_members::Type);
  if (type == config_members::RootCert) {
    IrohadConfig::InterPeerTls::RootCert root_cert;
    getValByKey(path, root_cert.path, obj, config_members::Path);
    dest = std::move(root_cert);
  } else if (type == config_members::InLengerCerts) {
    dest = IrohadConfig::InterPeerTls::FromWsv{};
  } else {
    throw JsonDeserializerException{std::string{
        "Unimplemented peer certificate provider type: '" + type + "'"}};
  }
}

template <>
inline void JsonDeserializerImpl::getVal<IrohadConfig::DbConfig>(
    const std::string &path,
    IrohadConfig::DbConfig &dest,
    const rapidjson::Value &src) {
  assert_fatal(src.IsObject(),
               path + " database config top element must be an object.");
  const auto obj = src.GetObject();
  getValByKey(path, dest.host, obj, config_members::Host);
  getValByKey(path, dest.port, obj, config_members::Port);
  getValByKey(path, dest.user, obj, config_members::User);
  getValByKey(path, dest.password, obj, config_members::Password);
  getValByKey(path, dest.working_dbname, obj, config_members::WorkingDbName);
  getValByKey(
      path, dest.maintenance_dbname, obj, config_members::MaintenanceDbName);
}

template <>
inline void JsonDeserializerImpl::getVal<IrohadConfig>(
    const std::string &path, IrohadConfig &dest, const rapidjson::Value &src) {
  assert_fatal(src.IsObject(),
               path + " Irohad config top element must be an object.");
  const auto obj = src.GetObject();
  getValByKey(path, dest.block_store_path, obj, config_members::BlockStorePath);
  getValByKey(path, dest.torii_port, obj, config_members::ToriiPort);
  getValByKey(path, dest.torii_tls_params, obj, config_members::ToriiTlsParams);
  getValByKey(path, dest.inter_peer_tls, obj, config_members::InterPeerTls);
  getValByKey(path, dest.internal_port, obj, config_members::InternalPort);
  getValByKey(path, dest.pg_opt, obj, config_members::PgOpt);
  getValByKey(path, dest.database_config, obj, config_members::DbConfig);
  getValByKey(
      path, dest.max_proposal_size, obj, config_members::MaxProposalSize);
  getValByKey(path, dest.proposal_delay, obj, config_members::ProposalDelay);
  getValByKey(path, dest.vote_delay, obj, config_members::VoteDelay);
  getValByKey(path, dest.mst_support, obj, config_members::MstSupport);
  getValByKey(
      path, dest.mst_expiration_time, obj, config_members::MstExpirationTime);
  getValByKey(
      path, dest.max_round_delay_ms, obj, config_members::MaxRoundsDelay);
  getValByKey(path,
              dest.stale_stream_max_rounds,
              obj,
              config_members::StaleStreamMaxRounds);
  getValByKey(path, dest.logger_manager, obj, config_members::LogSection);
  getValByKey(path, dest.initial_peers, obj, config_members::InitialPeers);
}

// ------------ end of getVal(path, dst, src) specializations ------------

std::string reportJsonParsingError(const rapidjson::Document &doc,
                                   const std::string &conf_path,
                                   const std::string &text) {
  const size_t error_offset = doc.GetErrorOffset();
  // This ensures the unsigned string beginning position does not cross zero:
  const size_t print_offset =
      std::max(error_offset, kBadJsonPrintOffsset) - kBadJsonPrintOffsset;
  std::string json_error_buf = text.substr(print_offset, kBadJsonPrintLength);
  return "JSON parse error [" + conf_path + "] " + "(near `" + json_error_buf
      + "'): " + std::string(rapidjson::GetParseError_En(doc.GetParseError()));
}

// TODO mboldyrev 2019.05.06 IR-465 make config loader testable
iroha::expected::Result<IrohadConfig, std::string> parse_iroha_config(
    const std::string &conf_path,
    std::shared_ptr<shared_model::interface::CommonObjectsFactory>
        common_objects_factory) {
  return iroha::readTextFile(conf_path) | [&](const auto &text)
             -> iroha::expected::Result<IrohadConfig, std::string> {
    const rapidjson::Document doc{[&text]() {
      rapidjson::Document doc;
      doc.Parse(text.data(), text.size());
      return doc;
    }()};

    if (doc.HasParseError()) {
      return reportJsonParsingError(doc, conf_path, text);
    }

    JsonDeserializerImpl parser(common_objects_factory);
    try {
      return parser.deserialize<IrohadConfig>(doc);
    } catch (JsonDeserializerException e) {
      return e.what();
    };
  };
}
