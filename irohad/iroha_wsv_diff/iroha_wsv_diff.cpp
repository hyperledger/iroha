/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gflags/gflags.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "ametsuchi/impl/pool_wrapper.hpp"
#include "ametsuchi/impl/rocksdb_common.hpp"
#include "common/result_try.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "logger/logger_spdlog.hpp"
#include "main/impl/pg_connection_init.hpp"
#include "main/impl/rocksdb_connection_init.hpp"

using std::cout, std::cerr, std::endl;
using std::ostream;
using std::string_view;
using namespace std::string_view_literals;
using namespace iroha;
using namespace iroha::ametsuchi;
using namespace iroha::ametsuchi::fmtstrings;
using json = nlohmann::json;

///////////////////////////////////
// Todo c++20
// template <class T>
// concept Collection = requires(T&& t) {
//    t.begin();
//    t.end();
// };

template <typename NonContainer>
struct is_container : std::false_type {};
template <typename... Ts>
struct is_container<std::list<Ts...>> : std::true_type {};
template <typename... Ts>
struct is_container<std::vector<Ts...>> : std::true_type {};
template <typename... Ts>
struct is_container<std::set<Ts...>> : std::true_type {};

template <class C>
auto operator<<(std::ostream &os, C const &coll)
    -> std::enable_if_t<is_container<C>::value, std::ostream &> {
  os << "[";
  auto comma = "";
  for (auto const &element : coll) {
    os << comma << element;
    comma = ", ";
  }
  return os << "]";
}
///////////////////////////////////

namespace {
  std::string tolower(std::string_view src) {
    std::string dst;
    dst.reserve(src.size());
    for (auto const c : src) dst += (char)std::tolower(c);
    return dst;
  }
  std::string &tolower(std::string &srcdst) {
    for (auto &c : srcdst) c = (char)std::tolower(c);
    return srcdst;
  }
  std::string &&tolower(std::string &&srcdst) {
    tolower(srcdst);
    return std::move(srcdst);
  }
  template <typename CharT, size_t sz>
  constexpr auto tolower(CharT const (&str)[sz]) {
    std::array<CharT, sz> ret;
    const CharT *p = str;
    while (*p) ret[p - str] = std::tolower(*p++);
    return ret;
  }
}  // namespace

static bool ValidateNonEmpty(const char *flagname, std::string const &str) {
  return not str.empty();
}
// NOLINTNEXTLINE
DEFINE_string(pg_opt,
              "",
              // "dbname=iroha_default host=localhost port=5432 user=postgres "
              // "password=postgres",
              "Specify Postgres options line as in Irohad config file");
DEFINE_validator(pg_opt, &ValidateNonEmpty);
// NOLINTNEXTLINE
DEFINE_string(rocksdb_path, "", "Specify path to RocksDB");
DEFINE_validator(rocksdb_path, &ValidateNonEmpty);
DEFINE_bool(ignore_checking_with_schema_version, false, "Should schema version be checked");

logger::LoggerManagerTreePtr getDefaultLogManager() {
  return std::make_shared<logger::LoggerManagerTree>(logger::LoggerConfig{
      logger::LogLevel::kInfo, logger::getDefaultLogPatterns()});
}

// Check:
// Domains
// Accounts
// Accounts' assets
// Signatories
// Roles, permissions
//

std::shared_ptr<iroha::ametsuchi::PoolWrapper> pg_pool_wrapper_;
std::shared_ptr<iroha::ametsuchi::RocksDBContext> db_context_;

expected::Result<void> initialize() try {
  logger::LoggerManagerTreePtr log_manager = getDefaultLogManager();
  logger::LoggerPtr log = log_manager->getChild("")->getLogger();

  IROHA_EXPECTED_TRY_GET_VALUE(
      pool_wrapper,
      PgConnectionInit::init(
          StartupWsvDataPolicy::kReuse,
          PostgresOptions(
              FLAGS_pg_opt,
              "iroha_default",
              log_manager->getChild("PostgresOptions")->getLogger()),
          log_manager,
          true));
  pg_pool_wrapper_ = std::move(pool_wrapper);

  IROHA_EXPECTED_TRY_GET_VALUE(
      rdb_port,
      RdbConnectionInit::init(StartupWsvDataPolicy::kReuse,
                              RocksDbOptions{FLAGS_rocksdb_path},
                              log_manager));
  db_context_ =
      std::make_shared<ametsuchi::RocksDBContext>(std::move(rdb_port));

  return {};
} catch (std::exception const &ex) {
  return expected::makeError(ex.what());
}

#undef CHECK_EQUALS
#undef STR
#undef STRX
#define STRX(x) #x
#define STR(x) STRX(x)
#define PRINT_NAME_HAVE_DIFFERENT(name, x, y) \
  fmt::print(name " have different " STR(x) ": '{}' and '{}'\n", (x), (y))
#define TYPES_PRINT_NAME_HAVE_DIFFERENT(type, name, x, y)               \
  fmt::print(type "-s '{}' have different " STR(x) ": '{}' and '{}'\n", \
             (name),                                                    \
             (x),                                                       \
             (y))

#define CHECK_EQUALS(name, x, y)           \
  if ((x) != (y)) {                        \
    PRINT_NAME_HAVE_DIFFERENT(name, x, y); \
    checked_result = false;                \
  }
#define CHECK_EQUALS_RETURN(name, x, y)    \
  if ((x) != (y)) {                        \
    PRINT_NAME_HAVE_DIFFERENT(name, x, y); \
    return false;                          \
  }
#define CHECK_EQUALS_NAMED(type, name, x, y)               \
  if ((x) != (y)) {                                        \
    TYPES_PRINT_NAME_HAVE_DIFFERENT(type, (name), x, (y)); \
    checked_result = false;                                \
  }
#define CHECK_EQUALS_STR(type, name, x, y)               \
  if ((x) != (y)) {                                      \
    TYPES_PRINT_NAME_HAVE_DIFFERENT(                     \
        type, (name), short_string(x), short_string(y)); \
    checked_result = false;                              \
  }
#define CHECK_EQUALS_JSON(type, name, x, y)                \
  if ((x) != (y)) {                                        \
    auto xd = (x).dump();                                  \
    auto yd = (y).dump();                                  \
    TYPES_PRINT_NAME_HAVE_DIFFERENT(                       \
        type, (name), short_string(xd), short_string(yd)); \
    checked_result = false;                                \
  }
#define CHECK_EQUAL_RANGES(type, x, y)                        \
  if (not xequal((x), (y), [](auto const &l, auto const &r) { \
        return l.check_equals(r);                             \
      })) {                                                   \
    fmt::print(type "-s have different " STR(x) ".\n");       \
    checked_result = false;                                   \
  }
#define COUNT_INEQUALITIES(type, name, x, y)                 \
  if ((x) != (y)) {                                          \
    ++inequalities_counter;                                  \
    TYPES_PRINT_NAME_HAVE_DIFFERENT(type, (name), (x), (y)); \
  }

template <class C1, class C2>
auto xequal(C1 &&c1, C2 &&c2) {
  using namespace std;
  return std::equal(begin(forward<C1>(c1)),
                    end(forward<C1>(c1)),
                    begin(forward<C2>(c2)),
                    end(forward<C2>(c2)));
}
template <class C1, class C2, class F>
auto xequal(C1 &&c1, C2 &&c2, F &&pred) {
  using namespace std;
  return std::equal(forward<C1>(c1).begin(),
                    forward<C1>(c1).end(),
                    forward<C2>(c2).begin(),
                    forward<C2>(c2).end(),
                    forward<F>(pred));
}

struct short_string {
  std::string_view sstr, dots;
  short_string(string_view sv) {
    sstr = sv.substr(0, 80);
    dots = sstr.size() < sv.size() ? "..." : "";
  }
  friend std::ostream &operator<<(std::ostream &os, short_string const &s) {
    return os << s.sstr << s.dots;
  }
};
template <>
struct fmt::formatter<short_string> {
  constexpr auto parse(format_parse_context &ctx) {
    return ctx.begin();
  }
  template <typename FormatContext>
  auto format(const short_string &s, FormatContext &ctx) {
    return format_to(ctx.out(), "{}{}", s.sstr, s.dots);
  }
};

std::string_view get_unquoted_key(string_view &key) {
  using namespace fmtstrings;
  assert(key.size() and key.starts_with(kDelimiter));
  auto const delim_sz = kDelimiter.size();
  auto ret = key.substr(delim_sz, key.find(kDelimiter, delim_sz) - delim_sz);
  key = key.substr(ret.size() + delim_sz * 2);
  return ret;
}

template <typename _CharT, typename _Traits, typename _Alloc>
inline void unquote(std::basic_string<_CharT, _Traits, _Alloc> &data) {
  _CharT const *rptr = data.data();
  _CharT *wptr = (_CharT *)rptr;
  if (rptr[0] != _CharT('\0'))
    do {
      rptr += *rptr == _CharT('\\') ? 1ul : 0ul;
      *wptr++ = *rptr;
    } while (*rptr++ != _CharT('\0'));
  data.resize(data.size() - size_t(rptr - wptr));
}

struct Peer {
  std::string pubkey;
  std::string address;
  mutable std::string tls;

  bool operator<(Peer const &p) const {
    return pubkey < p.pubkey;
  }
  friend ostream &operator<<(ostream &os, Peer const &p) {
    return os << "\n  "
              << "pubkey:" << p.pubkey << " address:" << p.address
              << " tls:" << p.tls;
  }
  static Peer from_soci_row(soci::row const &row) {
    Peer p;
    row >> p.pubkey >> p.address;
    if (row.get_indicator(2) != soci::i_null)
      row >> p.tls;
    return p;
  }
  bool check_equals(Peer const &o) const {
    CHECK_EQUALS_RETURN("Peers", pubkey, o.pubkey)
    CHECK_EQUALS_RETURN("Peers", address, o.address)
    CHECK_EQUALS_RETURN("Peers", tls, o.tls)
    return true;
  }
};
struct Role {
  std::string name;
  std::string permissions;

  bool operator<(Role const &o) const {
    return name < o.name;
  }
  friend ostream &operator<<(ostream &os, Role const &r) {
    return os << "\n  "
              << "name:" << r.name << " permisions:" << r.permissions;
  }
  static Role from_soci_row(soci::row const &r) {
    Role o;
    r >> o.name >> o.permissions;
    return o;
  }
  static Role from_key_value(string_view &key, string_view val) {
    return Role{std::string{get_unquoted_key(key)}, std::string(val)};
  }
  bool check_equals(Role const &o) const {
    bool checked_result = true;
    CHECK_EQUALS_RETURN("Role-s", name, o.name)
    CHECK_EQUALS_NAMED("Role", name, permissions, o.permissions)
    return checked_result;
  }
};
struct AssetPrecision {
  std::string name;
  mutable long double precision;

  bool operator<(AssetPrecision const &o) const {
    return name < o.name;
  }
  friend ostream &operator<<(ostream &os, AssetPrecision const &a) {
    return os << a.name << ":" << a.precision;
  }
  bool check_equals(AssetPrecision const &o) const {
    CHECK_EQUALS_RETURN("AssetPrecision-s", name, o.name)
    CHECK_EQUALS_RETURN("AssetPrecision-s", precision, o.precision)
    return true;
  }
};
struct AssetQuantity {
  std::string name;
  mutable double quantity;  // maybe long double

  bool operator<(AssetQuantity const &o) const {
    return name < o.name;
  }
  friend ostream &operator<<(ostream &os, AssetQuantity const &a) {
    return os << a.name << ":" << a.quantity;
  }
  static AssetQuantity from_key_value(string_view &key, string_view val) {
    auto name = get_unquoted_key(key);
    assert(key.empty());
    return AssetQuantity{std::string(name),
                         std::stod(std::string(val))};  // maybe stold
  }
  bool check_equals(AssetQuantity const &o) const {
    CHECK_EQUALS_RETURN("AssetQuantity-s", name, o.name)
    bool checked_result = true;
    CHECK_EQUALS_NAMED("AssetQuantity", name, quantity, o.quantity);
    return checked_result;
  }
};
struct GrantablePermissions {
  std::string permittee_account_id;
  std::string permission_bits;
  bool operator<(GrantablePermissions const &o) const {
    if (permittee_account_id == o.permittee_account_id)
      return permission_bits < o.permission_bits;
    return permittee_account_id < o.permittee_account_id;
  }
  bool operator==(GrantablePermissions const &o) const {
    return permittee_account_id == o.permittee_account_id
        and permission_bits == o.permission_bits;
  }
  bool operator!=(GrantablePermissions const &o) const {
    return permittee_account_id != o.permittee_account_id
        and permission_bits != o.permission_bits;
  }
  int count_inequalities(GrantablePermissions const &o) const {
    int inequalities_counter = 0;
    COUNT_INEQUALITIES("GrantablePermissions",
                       "",
                       permittee_account_id,
                       o.permittee_account_id)
    COUNT_INEQUALITIES(
        "GrantablePermissions", "", permission_bits, o.permission_bits)
    return inequalities_counter;
  }
  friend std::ostream &operator<<(std::ostream &os,
                                  const GrantablePermissions &gp) {
    return os << "{" << gp.permittee_account_id << ":" << gp.permission_bits
              << "}";
  }
};
template <>
struct fmt::formatter<GrantablePermissions> {
  constexpr auto parse(format_parse_context &ctx) {
    return ctx.begin();
  }
  template <typename FormatContext>
  auto format(const GrantablePermissions &gp, FormatContext &ctx) {
    return format_to(
        ctx.out(), "{{{}:{}}}", gp.permittee_account_id, gp.permission_bits);
  }
};

struct Account {
  std::string name;
  mutable nlohmann::json details_json = nlohmann::json::parse("{}");
  mutable long long quorum = 0;
  mutable std::set<AssetQuantity> assetsquantity;
  mutable std::set<std::string> roles;
  mutable std::set<std::string> signatories;
  mutable std::set<GrantablePermissions> grantable_permissions;

  bool operator<(Account const &o) const {
    return name < o.name;
  }
  friend ostream &operator<<(ostream &os, Account const &a) {
    auto jdump = a.details_json.dump();
    return os << "\n    " << a.name << ":"
              << "\n     details[" << jdump.size() << "]:'" << jdump << "'"
              << "\n     quorum:" << a.quorum << "\n     assets["
              << a.assetsquantity.size() << "]:[" << a.assetsquantity << "]"
              << "\n     roles[" << a.roles.size() << "]:[" << a.roles << "]"
              << "\n     grantable_permissions["
              << a.grantable_permissions.size() << "]:["
              << a.grantable_permissions << "]"
              << "\n     signatories[" << a.signatories.size() << "]:["
              << a.signatories << "]";
  }
  void from_key_value(string_view key, string_view /*val*/) {
    name = key.substr(0, key.find('/'));
    key = key.substr(name.size() + 1);
  }
  bool check_equals(Account const &o) const {
    bool checked_result = true;
    int inequalities_counter = 0;
    if (name != o.name) {
      fmt::print("Accounts have different name: '{}' and '{}'\n", name, o.name);
      ++inequalities_counter;
      return false;
    }
    CHECK_EQUALS_JSON("Accounts", name, details_json, o.details_json)
    CHECK_EQUALS_NAMED("Accounts", name, quorum, o.quorum)
    if (assetsquantity.size() != o.assetsquantity.size()) {
      fmt::print(
          "Accounts '{}' have different sizes of assetsquantity: '{}' and "
          "'{}'\n",
          name,
          assetsquantity.size(),
          o.assetsquantity.size());
      ++inequalities_counter;
      return false;
    }
    if (not xequal(
            assetsquantity, o.assetsquantity, [](auto const &l, auto const &r) {
              return l.check_equals(r);
            })) {
      fmt::print("Accounts '{}' have different assetsquantity\n", name);
      ++inequalities_counter;
      return false;
    }
    if (not xequal(
            signatories, o.signatories, [&](auto const &l, auto const &r) {
              if (l != r) {
                fmt::print(
                    "Accounts '{}' have different signatories '{}' and '{}'\n",
                    name,
                    l,
                    r);
                return false;
              }
              return true;
            })) {
      fmt::print("Accounts '{}' have different signatories.\n", name);
      ++inequalities_counter;
    }
    if (not xequal(roles, o.roles, [&](auto const &l, auto const &r) {
          if (l != r) {
            fmt::print("Accounts '{}' have different roles '{}' and '{}'\n",
                       name,
                       l,
                       r);
            return false;
          }
          return true;
        })) {
      fmt::print("Accounts '{}' have different roles.\n", name);
      ++inequalities_counter;
    }
    if (not xequal(grantable_permissions,
                   o.grantable_permissions,
                   [&](auto const &l, auto const &r) {
                     if (l != r) {
                       fmt::print(
                           "Accounts '{}' have different grantable_permissions "
                           "'{}' and '{}'\n",
                           name,
                           l,
                           r);
                       return false;
                     }
                     return true;
                   })) {
      fmt::print(
          "Accounts '{}' have different grantable_permissions: sizes are {} "
          "and {}\n",
          name,
          grantable_permissions.size(),
          o.grantable_permissions.size());
      ++inequalities_counter;
    }
    return checked_result;
  }
};
struct Domain {
  std::string name;
  mutable std::string default_role;
  mutable std::set<Account> accounts;
  mutable std::set<AssetPrecision> assets_precision;

  bool operator<(Domain const &o) const {
    return name < o.name;
  }
  friend ostream &operator<<(ostream &os, Domain const &d) {
    // clang-format off
      os << "\n  " << d.name << ":"
         << "\n   default_role:" << d.default_role
         << "\n   accounts[" << d.accounts.size() << "]: [" << d.accounts << "]"
         << "\n   assets_precision: [" << d.assets_precision << "]\n";
    // clang-format on
    return os;
  }
  static Domain from_soci_row(soci::row const &row) {
    Domain d;
    row >> d.name >> d.default_role;
    return d;
  }
  bool check_equals(Domain const &other) const {
    if (name != other.name) {
      cout << "Domain names differ: '" << name << "' vs '" << other.name << "'"
           << endl;
      return false;
    }
    if (default_role != other.default_role) {
      cout << "Domain default_role differ: '" << default_role << "' vs '"
           << other.default_role << "'" << endl;
      return false;
    }
    if (not std::equal(
            begin(accounts),
            end(accounts),
            begin(other.accounts),
            end(other.accounts),
            [](auto const &l, auto const &r) { return l.check_equals(r); })) {
      fmt::print("Domains '{}' have different accounts.\n", name);
      return false;
    }
    if (not std::equal(
            begin(assets_precision),
            end(assets_precision),
            begin(other.assets_precision),
            end(other.assets_precision),
            [](auto const &l, auto const &r) { return l.check_equals(r); })) {
      fmt::print("Domains '{}' have different assets_precision.\n", name);
      return false;
    }
    return true;
  }
};

struct Wsv {
  std::string schema_version;
  unsigned long long top_block_height = 0;
  std::string top_block_hash;
  unsigned long long total_transactions_count = 0;
  std::set<Peer> peers;
  std::set<Role> roles;
  std::set<Domain> domains;

  // clang-format off
   friend ostream& operator<<(ostream& os, Wsv const& w){
      os << " schema_version:"<<w.schema_version<<"\n"
         << " top_block_height:"<<w.top_block_height<<"\n"
         << " top_block_hash:"<<w.top_block_hash<<"\n"
         << " total_transactions_count:"<<w.total_transactions_count<<"\n"
         << " peers["<<w.peers.size()<<"]:[ " << w.peers << " ]\n"
         << " roles["<<w.roles.size()<<"]:[ " << w.roles << " ]\n"
         << " domains["<<w.domains.size()<<"]:[ " << w.domains << " ]\n";
      return os;
   }
  // clang-format on

  [[nodiscard]] bool check_equals(Wsv const &other) const {
    bool checked_result = true;
    CHECK_EQUALS("Wsv-s", schema_version, other.schema_version);
    CHECK_EQUALS("Wsv-s", top_block_height, other.top_block_height);
    CHECK_EQUALS("Wsv-s", top_block_hash, other.top_block_hash);
    CHECK_EQUALS(
        "Wsv-s", total_transactions_count, other.total_transactions_count)
    CHECK_EQUAL_RANGES("Wsv", peers, other.peers)
    CHECK_EQUAL_RANGES("Wsv", roles, other.roles)
    CHECK_EQUAL_RANGES("Wsv", domains, other.domains)
    return checked_result;
  }

  Domain const &find_domain_by_name(std::string domain_id) {
    Domain dom_to_find;
    dom_to_find.name =
        std::move(domain_id);  // fixme do not copy, find by const&
    auto it_dom = domains.find(dom_to_find);
    assert(it_dom != end(domains));
    return *it_dom;
  }
  Account const &find_account_by_id(std::string account_id) {
    auto const &[acc_name, dom_id] = staticSplitId<2ull>(account_id, "@");
    assert(acc_name.size());
    assert(dom_id.size());
    auto &dom = find_domain_by_name(std::string(dom_id));
    Account acc_to_find;
    acc_to_find.name =
        std::move(account_id);  // fixme do not copy, find by const&
    auto it_acc = dom.accounts.find(acc_to_find);
    assert(it_acc != end(dom.accounts));
    return *it_acc;
  }

  bool from_rocksdb(RocksDbCommon &);
  bool from_postgres(soci::session &);
};

bool Wsv::from_rocksdb(RocksDbCommon &rdbc) {
  std::map<std::string, std::set<GrantablePermissions>>
      grant_perms_map;  // required because permittee domain could not exist at
                        // the moment of iteration
  std::map<const Account *, size_t> assets_counts, details_count;
  unsigned peers_count = 0;  // Just to assert integrity
  auto status = rdbc.enumerate(
      [&](auto const &it, size_t key_sz) {
        auto key =
            string_view(it->key().data() + key_sz, it->key().size() - key_sz);
        auto const val = string_view(it->value().data(), it->value().size());
        auto key_starts_with_and_drop = [&key](string_view sv) {
          if (sv.size() > key.size())
            return false;
          auto it_key = begin(key);
          auto it_sv = begin(sv);
          while (it_sv != end(sv) and *it_key == *it_sv) ++it_key, ++it_sv;
          if (it_sv == end(sv)) {
            key = key.substr(sv.size());
            return true;
          }
          return false;
        };
        // cout << "-- " << key << endl;
        if (key_starts_with_and_drop(RDB_F_VERSION)) {
          assert(key.empty());
          schema_version = std::string{val};
          if (! FLAGS_ignore_checking_with_schema_version)
          {
            assert(schema_version == "1#4#0" &&
                   "This version of iroha_wsv_diff can check WSV in RocksDB of version 1.4.0 only");
          }
        } else if (key_starts_with_and_drop(RDB_NETWORK)) {
          if (key_starts_with_and_drop(RDB_PEERS)) {
            if (key_starts_with_and_drop(RDB_ADDRESS)) {
              auto pubkey = get_unquoted_key(key);
              assert(key.empty());
              auto const peer_was_inserted [[maybe_unused]] =
                  peers.insert(Peer{std::string(pubkey), std::string(val), ""})
                      .second;
              assert(peer_was_inserted);
            } else if (key_starts_with_and_drop(RDB_TLS)) {
              auto pubkey = get_unquoted_key(key);
              assert(key.empty());
              auto it_peer = peers.find(Peer{std::string(pubkey), "", ""});
              assert(it_peer != end(peers));  // must exist
              it_peer->tls = std::string(val);
            } else if (key_starts_with_and_drop(RDB_F_PEERS_COUNT)) {
              assert(key.empty());
              peers_count = std::stoull(std::string(val));
            } else {
              assert(0 && "unexpected key under RDB_ROOT RDB_WSV RDB_PEERS");
            }
          }  // RDB_PEERS
          else if (key_starts_with_and_drop(RDB_STORE)) {
            if (key_starts_with_and_drop(RDB_F_TOP_BLOCK)) {
              assert(key.empty());
              auto height_str = val.substr(0, val.find('#'));
              top_block_height = stoull(std::string(height_str));
              top_block_hash = std::string(val.substr(height_str.size() + 1));
            } else if (key_starts_with_and_drop(RDB_F_TOTAL_COUNT)) {
              assert(key.empty());
              assert(0 && "unexpected key nsV");
            } else {
              assert(0);
            }
          } else {
            cout << "Unexpected key '" << key << "'" << endl;
            assert(0);
          }
        }  // RDB_NETWORK
        else if (key_starts_with_and_drop(RDB_ROLES)) {
          auto const role_was_inserted [[maybe_unused]] =
              roles.emplace(Role::from_key_value(key, val)).second;
          assert(key.empty());
          assert(role_was_inserted && "Role was not inserted");
        } else if (key_starts_with_and_drop(RDB_DOMAIN)) {
          if (key_starts_with_and_drop(RDB_F_TOTAL_COUNT)) {
            unsigned long long domains_count [[maybe_unused]] =
                std::stoull(std::string(val));
            assert(domains.size() == domains_count);
          } else {  // if (key_starts_with_and_drop(fmtstrings::kDelimiter)) {
            auto domname = get_unquoted_key(key);
            auto [it_dom, inserted_dom] = domains.insert(
                Domain{std::string(domname), std::string(val), {}, {}});
            auto &dom = *it_dom;
            if (key.empty()) {
              assert(inserted_dom);
            } else {
              if (key_starts_with_and_drop(RDB_ACCOUNTS)) {
                auto accname = get_unquoted_key(key);
                Account acc_to_insert;
                acc_to_insert.name = (std::string(accname) += "@") += domname;
                auto [it_acc, inserted] = dom.accounts.insert(acc_to_insert);
                auto &acc = *it_acc;
                if (key_starts_with_and_drop(RDB_ASSETS)) {
                  auto const asset_was_inserted [[maybe_unused]] =
                      acc.assetsquantity
                          .emplace(AssetQuantity::from_key_value(key, val))
                          .second;
                  assert(key.empty());
                  assert(asset_was_inserted
                         && "AssetQuantity was not inserted");
                } else if (key_starts_with_and_drop(RDB_SIGNATORIES)) {
                  auto signame = get_unquoted_key(key);
                  assert(key.empty());
                  auto const inserted [[maybe_unused]] =
                      acc.signatories.emplace(tolower(signame)).second;
                  assert(inserted && "Signatory failed to insert");
                } else if (key_starts_with_and_drop(RDB_ROLES)) {
                  auto rolename = get_unquoted_key(key);
                  assert(key.empty());  // there must be no subkeys
                  auto flags = val;
                  (void)(flags);  // unused at the moment
                  auto const role_was_inserted [[maybe_unused]] =
                      acc.roles.insert(std::string(rolename)).second;
                  assert(role_was_inserted && "Role was not inserted");
                } else if (key_starts_with_and_drop(RDB_OPTIONS)) {
                  if (key_starts_with_and_drop(RDB_F_QUORUM)) {
                    acc.quorum = stoll(std::string(val));
                  } else if (key_starts_with_and_drop(RDB_F_ASSET_SIZE)) {
                    assets_counts[&acc] = stoull(std::string(val));
                  } else if (key_starts_with_and_drop(
                                 RDB_F_TOTAL_COUNT)) {  // kAccountDetailsCount
                    details_count[&acc] = stoull(std::string(val));
                  } else {
                    assert(0 && "unexpected");
                  }
                  assert(key.empty());
                } else if (key_starts_with_and_drop(RDB_DETAILS)) {
                  auto *jso = &acc.details_json;
                  do {
                    auto subkey = get_unquoted_key(key);
                    jso = &((*jso)[std::string(subkey)]);
                  } while (key.size());
                  std::string unquoted_val(val);
                  unquote(unquoted_val);
                  *jso = unquoted_val;
                  assert(key.empty());
                } else if (key_starts_with_and_drop(RDB_GRANTABLE_PER)) {
                  auto permittee_acc = get_unquoted_key(key);
                  assert(key.empty());
                  auto peracc_id = (std::string(
                      permittee_acc));  // += "@") += permittee_dom;
                  GrantablePermissions gp{peracc_id, std::string(val)};
                  grant_perms_map[acc.name].insert(gp);
                } else {
                  assert(0 && "unexpected key under wDa");
                }
              } else if (key_starts_with_and_drop(RDB_ASSETS)) {
                auto assname = get_unquoted_key(key);
                assert(key.empty());
                auto asset_id = ((std::string(assname) += "#") += domname);
                AssetPrecision ap{asset_id, std::stold(std::string(val))};
                auto const asset_precision_was_inserted [[maybe_unused]] =
                    dom.assets_precision.insert(ap).second;
                assert(asset_precision_was_inserted
                       && "AssetPrecision was not inserted");
              } else {
                assert(0 && "unexpected key under wD, acceptable wDa,wDx");
              }
            }
          }
        }  // RDB_DOMAIN
        else if (key_starts_with_and_drop(RDB_TRANSACTIONS)) {
          if (key_starts_with_and_drop(RDB_F_TOTAL_COUNT)) {
            total_transactions_count =
                std::stoull(std::string(val));  // fixme do not create string
          } else if (key_starts_with_and_drop(RDB_ACCOUNTS)) {
#if 0  /// This could be used for future database layout validaition
       /// and future deeper transactions index validation.
            auto accid = get_unquoted_key(key);
            auto& acc = find_account_by_id(std::string(accid));
            (void)acc;
            if (key_starts_with_and_drop(RDB_F_TOTAL_COUNT)) {
              // TODO select count(*) from tx_positions where
              // creator_id='did@identity' and asset_id is NULL
              key = {};
            } else if (key_starts_with_and_drop(RDB_POSITION)) {
              // This is to validate DB layout
              key = {};
            } else if (key_starts_with_and_drop(RDB_TIMESTAMP)) {
              // This is to validate DB layout
              key = {};
            } else {
              fmt::print("Wrong RocksDB layout: unexpected key '{}'\n",
                         string_view(it->key().data() + key_sz,
                                     it->key().size() - key_sz));
              std::abort();
              assert(0 and "Wrong DB layout- unexpected key");
            }
#else
            key = {};
#endif
          } else if (key_starts_with_and_drop(RDB_STATUSES)) {
            // This is to validate DB layout
            key = {};
          } else {
            fmt::print("Wrong RocksDB layout: unexpected key '{}'\n",
                       string_view(it->key().data() + key_sz,
                                   it->key().size() - key_sz));
            std::abort();
            assert(
                0
                and "Wrong DB layout - unexpected key under RDB_TRANSACTIONS");
          }
        }  // RDB_TRANSACTIONS
        else if (key_starts_with_and_drop(RDB_SETTINGS)) {
          // This is to validate DB layout
          key = {};
        } else {
          assert(0
                 && "unexpected key under RDB_ROOT RDB_WSV '" RDB_ROOT RDB_WSV
                    "'");
        }
        assert(key.empty());
        return true;
      },
      iroha::ametsuchi::RocksDBPort::ColumnFamilyType::kWsv,
      RDB_ROOT RDB_WSV);
  for (auto &[permaccid, gp_set] : grant_perms_map) {
    auto &acc = find_account_by_id(permaccid);
    acc.grantable_permissions = std::move(gp_set);
  }
  for ([[maybe_unused]] auto &acc_assnt : assets_counts) {
    assert(acc_assnt.first->assetsquantity.size() == acc_assnt.second);
  }
  for (auto &[acc, detcnt] : details_count) {
    size_t wrcnt = 0;
    for (auto &writer : acc->details_json) wrcnt += writer.size();
    if (wrcnt != detcnt) {
      cout << "acc->name" << acc->name << endl;
      cout << acc->details_json.dump(2) << endl;
      cout << "acc->details_json[writer].size():" << wrcnt
           << " detcnt:" << detcnt << endl;
    }
    assert(wrcnt == detcnt);
  }
  assert(peers_count == peers.size());
  return status.ok();
}

bool Wsv::from_postgres(soci::session &sql) {
  using namespace soci;

  struct {
    std::string ma, mi, pa;
  } version;
  sql << "SELECT iroha_major,iroha_minor,iroha_patch FROM schema_version",
      into(version.ma), into(version.mi), into(version.pa);
  schema_version = ((((std::string{} += version.ma) += "#") += version.mi) +=
                    "#") += version.pa;

  sql << "select height,hash from top_block_info", into(top_block_height),
      into(top_block_hash);

  // Three different ways to obtain total number of transactions.
  sql << "select count(distinct hash) from tx_positions",
      into(total_transactions_count);
  unsigned long long counter;
  sql << "select count(*) from tx_positions where asset_id is null",
      into(counter);
  assert(total_transactions_count == counter);
  sql << "select count(*) from tx_status_by_hash where status = true",
      into(counter);
  assert(total_transactions_count == counter);

  rowset<row> rs = (sql.prepare << "SELECT * FROM peer");
  for (auto &r : rs) {
    auto const inserted [[maybe_unused]] =
        peers.insert(Peer::from_soci_row(r)).second;
    assert(inserted && "Peer was not inserted");
  }

  rs = (sql.prepare << "SELECT * FROM domain");
  for (auto &r : rs) {
    auto const inserted [[maybe_unused]] =
        domains.emplace(Domain::from_soci_row(r)).second;
    assert(inserted && "Domain was not inserted");
  }

  rs = (sql.prepare << "SELECT * FROM role_has_permissions");
  for (auto &r : rs) {
    auto const inserted [[maybe_unused]] =
        roles.insert(Role::from_soci_row(r)).second;
    assert(inserted && "Role was not inserted");
  }

  rs = (sql.prepare << "SELECT * FROM asset");
  for (auto &r : rs) {
    std::string asset_id, dom_id;
    int32_t precision;
    r >> asset_id >> dom_id >> precision;
    Domain dom_to_find;
    dom_to_find.name = dom_id;
    auto it_dom = domains.find(dom_to_find);
    assert(it_dom != end(domains));
    auto &dom = *it_dom;
    auto const inserted [[maybe_unused]] =
        dom.assets_precision
            .insert(AssetPrecision{asset_id, (long double)precision})
            .second;
    assert(inserted && "AssetPrecision was not inserted");
  }

  rs = (sql.prepare << "SELECT * FROM account");
  for (auto &r : rs) {
    std::string account_id, dom_id, data;
    int32_t quorum;
    r >> account_id >> dom_id >> quorum >> data;
    auto &dom = find_domain_by_name(std::move(dom_id));
    Account acc_to_insert;
    acc_to_insert.name = std::move(account_id);
    acc_to_insert.quorum = std::move(quorum);
    acc_to_insert.details_json = json::parse(data);
    auto const inserted [[maybe_unused]] =
        dom.accounts.insert(acc_to_insert).second;
    assert(inserted && "Account was not inserted");
  }

  rs = (sql.prepare << "SELECT * FROM account_has_asset");
  for (auto &r : rs) {
    std::string account_id, asset_id;
    double amount;
    r >> account_id >> asset_id >> amount;
    auto &acc = find_account_by_id(std::move(account_id));
    AssetQuantity aq_to_insert{std::move(asset_id), std::move(amount)};
    auto const inserted [[maybe_unused]] =
        acc.assetsquantity.insert(aq_to_insert).second;
    assert(inserted && "AssetQuantity was not inserted");
  }

  rs = (sql.prepare << "SELECT * FROM account_has_signatory");
  for (auto &r : rs) {
    std::string account_id, public_key;
    r >> account_id >> public_key;
    auto &acc = find_account_by_id(std::move(account_id));
    auto const inserted [[maybe_unused]] =
        acc.signatories.insert(tolower(std::move(public_key))).second;
    assert(inserted
           && "public_key was not inserted to domains.accounts.signatories");
  }

  rs = (sql.prepare << "SELECT * FROM account_has_roles");
  for (auto &r : rs) {
    std::string account_id, role_id;
    r >> account_id >> role_id;
    auto &acc = find_account_by_id(std::move(account_id));
    auto const inserted [[maybe_unused]] =
        acc.roles.insert(std::move(role_id)).second;
    assert(inserted
           && "Role was not inserted to domains[id].accounts[id].roles");
  }

  rs = (sql.prepare << "SELECT * FROM account_has_grantable_permissions");
  for (auto &r : rs) {
    std::string permitter_account_id;
    GrantablePermissions gp;
    r >> permitter_account_id >> gp.permittee_account_id >> gp.permission_bits;
    auto &acc = find_account_by_id(permitter_account_id);
    auto [it_gp, inserted] = acc.grantable_permissions.insert(gp);
    if (!inserted) {
      fmt::print("--gp {} already exist in acc {}: {}\n",
                 gp,
                 permitter_account_id,
                 *it_gp);
      cout << "acc.grantable_permissions:[" << acc.grantable_permissions << "]"
           << endl;
    }
    assert(inserted && "grantable_permissions failed to insert");
  }

  return true;
}

int wsv_check() try {
  using namespace std::chrono;

  cout << "Reading rocksdb... ";
  auto start_rd = std::chrono::system_clock::now();
  RocksDbCommon rdbc(db_context_);
  Wsv wsv_rocks;
  wsv_rocks.from_rocksdb(rdbc);
  cout << "in "
       << duration_cast<milliseconds>(system_clock::now() - start_rd).count()
       << "ms" << endl;
  std::ofstream(std::filesystem::current_path() / "rockdb.wsv")
      << "wsv_rocks:\n"
      << wsv_rocks << endl;
  // cout << "-----------------------" << endl;
  cout << "Reading postgres... ";
  auto start_pg = std::chrono::system_clock::now();
  soci::session sql(*pg_pool_wrapper_->connection_pool_);
  Wsv wsv_postgres;
  wsv_postgres.from_postgres(sql);
  cout << "in "
       << duration_cast<milliseconds>(system_clock::now() - start_pg).count()
       << "ms" << endl;
  std::ofstream(std::filesystem::current_path() / "postgres.wsv")
      << "wsv_postgres:\n"
      << wsv_postgres << endl;

  cout << "See detailed dumps in files rockdb.wsv and postgres.wsv" << endl;
  cout << "== VALIDATING ==" << endl;
  cout << "left is rocksdb, right is postgres" << endl;

  if (wsv_rocks.check_equals(wsv_postgres)) {
    // clang-format off
    cout << "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▓▓██████████▓▓▒░░░░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▓██████████████████▓▒░░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒███████████▓▓▓███▓▓▓▓█▓░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▓███████████████▓▓▓▓█████▒░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒████████▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▓█▓░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░░░░░░░▒░░░░░░░░░░░░░░░░░░░░░░░░░▒█████████▓▓▓▒▒▒▒▒▒▒░▒▒▒▒▓▓░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░░░░░░▓▒▒░░░░▓▒▒▒░░░░░░░░░░░░░░░▒▓█████████▓████▓▒▒▒▓▓▓▓▓▒▓▒░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░░░░░▒▓▒▒░░░▒▒▒▒▒░░░░░░░░░░░░░░░▓████████▓█▓▓▒▓██▒▒▒▓▓▓▓▓▒▓▒░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░░░▒▒▒▒▒▒░░▒▒▒▒▒▒░░░░░░░░░░░░░░░▓███████▓▓▒▒▒▒▓██▒▒▒▒▒▒▒▒▒▓░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░░░▓▒▒▒▒▒░░▒▒▒▒▒▒░░░░░░░░░░░░░░░░▓███████▓▓▒▒████▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░░▒▓▒▒▒▒▒░▓▒▒▒▒▒▒░░░░░░░░░░░░░░░░▒████████▓▓██████▓▓▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░░▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░████████████▓▓▓▓▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░░▓▒▒▒▒▒▒▒▒▒▒▓▒▒▒░░░░░░░░░░░░░░░░░░▒███████▓▓▓▓▓▓▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░░▓▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░██████▓▓██▓▓▓▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░▓█████▓▓▓▓▓▓▓▓▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░▒▒▒▒░░░░░░░░░░░░▓██████▓▓▓▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░▒▓▓▒▒░░░░░░░░░░░░░▓███████▓▓▓▓▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░░▒████████████▓▓▒▒▒░░░░░░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░▒▒███████████▓▓▒▒▒▒▒▒▓░░░░░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░█▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░▒▒▒▒▓▓█████████▓▓▓▓▓▓▓▓██▓░░░░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░░█▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░▒▓█████████▓██████████████████▓▓▒▒▒░░░░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░▒██▓▓▓▓▓▓▓▓▓▒▒▒░░░░▒▒▒▒▓▓▒▒▒▒▓▓▓▓▓▓▓▓█▓█████████████▓▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░\n"
            "░░░░░░░░░░░░░▓▓▓▓▓▓▓▓▓▓▓▒░░░░▒▒▓▒▒▒░▒▒▓▓▓▓▓▓▓▓▓▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░\n"
            "░░░░░░░░░░░▒█▓▓▓▓▓▓▒▒▒▓░░░▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░\n"
            "░░░░░░░░░░▒████▓▓▓▒▒▒▓▒░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░\n"
            "░░░░░░░░░▒██████▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░\n"
            "░░░░░░░░▒██████▓▓▓▓▓▓▓▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░\n"
            "░░░░░░░░██████▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░\n"
            "░░░░░░░██████▓▓▓▒▓▓▒▒▓▓▒▒▒▓█▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░\n"
            "░░░░░▒█████▓▓▓▓▓▓▓▓█▓▓▒▒▒▒▒▒▓█▓▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░\n";
    // clang-format on
    cout << "~~~ WSV-s are same. Enjoy Iroha with RocksDB ~~~" << endl;
    return 0;
  } else {
    cout << "~~~ WSV-s DIFFER!!! ~~~" << endl;
    cout << "For future investigation use difftool on files rocksdb.wsv and "
            "postgres.wsv. Just like:"
         << endl;
    cout << "   diff <(tail -n+2 postgres.wsv) <(tail -n+2 rockdb.wsv)" << endl;
    cout << "(Here command tail is to drop first line.)" << endl;
    return 1;
  }

} catch (std::exception const &ex) {
  cerr << "Caught exception: " << ex.what() << endl;
  return 1;
}

int main(int argc, char *argv[]) {
  gflags::SetVersionString("0.1");
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  if (auto result = initialize(); expected::hasError(result)) {
    cerr << "ERROR initialize: " << result.assumeError() << endl;
    return 1;
  }

  int status = wsv_check();

  // Required becouse RocksdbContext throws when destructed implicitly in exit()
  db_context_.reset();
  pg_pool_wrapper_.reset();

  return status;
}
