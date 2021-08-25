/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fmt/format.h>
#include <gflags/gflags.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>

#include "ametsuchi/impl/block_query_base.hpp"
#include "ametsuchi/impl/flat_file/flat_file.hpp"
#include "ametsuchi/impl/flat_file_block_storage.hpp"
#include "ametsuchi/impl/in_memory_block_storage_factory.hpp"
#include "ametsuchi/impl/pool_wrapper.hpp"
#include "ametsuchi/impl/rocksdb_common.hpp"
#include "ametsuchi/impl/rocksdb_storage_impl.hpp"
#include "ametsuchi/impl/tx_presence_cache_impl.hpp"
#include "ametsuchi/impl/wsv_restorer_impl.hpp"
#include "ametsuchi/vm_caller.hpp"
#include "backend/protobuf/proto_block_json_converter.hpp"
#include "backend/protobuf/proto_query_response_factory.hpp"
#include "backend/protobuf/proto_tx_status_factory.hpp"
#include "common/bind.hpp"
#include "common/irohad_version.hpp"
#include "common/result_try.hpp"
#include "consensus/yac/consistency_model.hpp"
#include "consensus/yac/supermajority_checker.hpp"
#include "generator/generator.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "logger/logger_spdlog.hpp"
#include "main/impl/consensus_init.hpp"
#include "main/impl/rocksdb_connection_init.hpp"
#include "main/impl/storage_init.hpp"
#include "main/startup_params.hpp"  //for StartupWsvDataPolicy
#include "validation/impl/chain_validator_impl.hpp"
#include "validation/impl/stateful_validator_impl.hpp"
#include "validators/always_valid_validator.hpp"
#include "validators/default_validator.hpp"
#include "validators/protobuf/proto_block_validator.hpp"
#include "validators/protobuf/proto_query_validator.hpp"
#include "nlohmann/json.hpp"

#define STR(y) STRH(y)
#define STRH(x) #x

using std::cout, std::cerr, std::endl;
using std::ifstream, std::ofstream;
using std::string_view;
namespace fs = std::filesystem;
using namespace iroha;
using namespace iroha::ametsuchi;

// NOLINTNEXTLINE
DEFINE_string(block_store_path,
              "/tmp/block_store",
              "Specify path to block store");
// NOLINTNEXTLINE
DEFINE_string(rocksdb_path, "rocks.db", "Specify path to RocksDB");
// NOLINTNEXTLINE
DEFINE_bool(force, false, "override blocks in RocksDB blockstore if exist");
// NOLINTNEXTLINE
DEFINE_string(export,
              "NOEXPORT",
              "Export block store to specified directory, default CWD");

#define CHECK_RETURN(cond, ...)                                                \
  if (!(cond)) {                                                               \
    fmt::print("ERROR in " __FILE__ ":" STR(__LINE__) " - {}\n", __VA_ARGS__); \
    return 1;                                                                  \
  }
#define CHECK_RETURN_FMT(cond, forma, ...)                    \
  if (!(cond)) {                                              \
    fmt::print("ERROR in " __FILE__ ":" STR(__LINE__) " - "); \
    fmt::print(FMT_STRING(forma), __VA_ARGS__);               \
    fmt::print("\n");                                         \
    return 1;                                                 \
  }
#define CHECK_TRY_GET_VALUE(name, ...)                                         \
  typename decltype(__VA_ARGS__)::ValueInnerType name;                         \
  if (auto _tmp_gen_var = (__VA_ARGS__);                                       \
      iroha::expected::hasError(_tmp_gen_var)) {                               \
    fmt::print("ERROR in " __FILE__ ":" STR(__LINE__) " - {}. Try --force.\n", \
               _tmp_gen_var.assumeError());                                    \
    return 1;                                                                  \
  } else {                                                                     \
    name = std::move(_tmp_gen_var.assumeValue());                              \
  }

template <>
struct fmt::formatter<DbError> {
  constexpr auto parse(format_parse_context &ctx) {
    return ctx.begin();
  }
  template <typename FormatContext>
  auto format(const DbError &e, FormatContext &ctx) {
    return format_to(ctx.out(), "{} (code:{})", e.description, e.code);
  }
};
template <>
struct fmt::formatter<fs::path> {
  constexpr auto parse(format_parse_context &ctx) {
    return ctx.begin();
  }
  template <typename FormatContext>
  auto format(const fs::path &p, FormatContext &ctx) {
    return format_to(ctx.out(), "{}", p.string());
  }
};
template <>
struct fmt::formatter<IrohadVersion> {
  constexpr auto parse(format_parse_context &ctx) {
    return ctx.begin();
  }
  template <typename FormatContext>
  auto format(const IrohadVersion &v, FormatContext &ctx) {
    return format_to(ctx.out(), "{}#{}#{}", v.major, v.minor, v.patch);
  }
};
template <typename O>
struct fmt::formatter<std::optional<O>> {
  constexpr auto parse(format_parse_context &ctx) {
    return ctx.begin();
  }
  template <typename FormatContext>
  auto format(const std::optional<O> &o, FormatContext &ctx) {
    return o ? format_to(ctx.out(), "{}", *o)
             : format_to(ctx.out(), "_nullopt_");
  }
};

template <class O>
std::ostream &operator<<(std::ostream &os, std::optional<O> const &o) {
  return o ? (os << *o) : (os << "_nullopt_");
}

int export_blocks(RocksDbCommon &rdbc) {
#if 0
   rdbc.enumerate(
       [](auto&& it, auto&& sz) {
          cout << "-- " << string_view(it->key().data(), it->key().size()) << " --- "
               << string_view(it->value().data(), it->value().size()) << endl;
       },
       "s");
#endif
  CHECK_TRY_GET_VALUE(cnt, forBlocksTotalCount(rdbc));
  assert(cnt);
  fs::create_directories(fs::absolute(FLAGS_export));
  uint64_t count = *cnt;
  uint64_t const total = count;
  while (count > 0) {
    CHECK_TRY_GET_VALUE(blkstr, forBlock(rdbc, count));
    assert(blkstr);
    auto outfilepath =
        fs::absolute(FLAGS_export) / fmt::format("{:016}", count);
    auto ofs = ofstream(outfilepath);
    CHECK_RETURN_FMT(ofs.is_open(), "Failed to open file '{}'", outfilepath);
    ofs << blkstr;
    CHECK_RETURN_FMT(ofs.good(), "Failed to write to file '{}'", outfilepath);
    --count;
  }
  cout << "Exported " << total << " blocks." << endl;
  return 0;
}

namespace {
  logger::LoggerManagerTreePtr getDefaultLogManager() {
    return std::make_shared<logger::LoggerManagerTree>(logger::LoggerConfig{
        logger::LogLevel::kInfo, logger::getDefaultLogPatterns()});
  }
  logger::LoggerManagerTreePtr log_manager = getDefaultLogManager();
  auto validators_log_manager = log_manager -> getChild("Validators");
}  // namespace

auto makeWsvRestorer() {
  using namespace iroha;
  using namespace iroha::consensus::yac;
  using namespace iroha::validation;
  using namespace shared_model::validation;
  static constexpr ConsistencyModel kConsensusConsistencyModel =
      ConsistencyModel::kCft;
  auto chain_validator = std::make_shared<ChainValidatorImpl>(
      getSupermajorityChecker(kConsensusConsistencyModel),
      validators_log_manager->getChild("Chain")->getLogger());
  auto block_validators_config_ =
      std::make_shared<ValidatorsConfig>(100000, true);
  auto interface_validator =
      std::make_unique<DefaultSignedBlockValidator>(block_validators_config_);
  auto proto_validator = std::make_unique<ProtoBlockValidator>();
  return std::make_shared<ametsuchi::WsvRestorerImpl>(
      std::move(interface_validator),
      std::move(proto_validator),
      chain_validator,
      log_manager->getChild("WsvRestorer")->getLogger());
}
expected::Result<std::shared_ptr<iroha::ametsuchi::Storage>, std::string>
makeStorage() {
  IROHA_EXPECTED_TRY_GET_VALUE(
      rdb_port,
      RdbConnectionInit::init(StartupWsvDataPolicy::kReuse,
                              RocksDbOptions{FLAGS_rocksdb_path},
                              log_manager));
  auto db_context_ =
      std::make_shared<ametsuchi::RocksDBContext>(std::move(rdb_port));
  std::shared_ptr<iroha::PendingTransactionStorage> pending_txs_storage_ =
      nullptr;  // CT-error std::make_shared<PendingTransactionStorageImpl>();
  std::shared_ptr<shared_model::interface::QueryResponseFactory>
      query_response_factory_ =
          std::make_shared<shared_model::proto::ProtoQueryResponseFactory>();
  std::optional<std::unique_ptr<iroha::ametsuchi::VmCaller>> vm_caller_;
#if 0 and defined(USE_BURROW)
  vm_caller_ = std::make_unique<iroha::ametsuchi::BurrowVmCaller>();
#endif
  std::optional<std::reference_wrapper<const iroha::ametsuchi::VmCaller>>
      vm_caller_ref;
  if (vm_caller_) {
    vm_caller_ref = *vm_caller_.value();
  }
  auto process_block =
      [](std::shared_ptr<shared_model::interface::Block const> block) {};
  IROHA_EXPECTED_TRY_GET_VALUE(storage,
                               initStorage(db_context_,
                                           pending_txs_storage_,
                                           query_response_factory_,
                                           FLAGS_block_store_path,
                                           vm_caller_ref,
                                           process_block,
                                           log_manager->getChild("Storage")));
  return {storage};
}
expected::Result<std::unique_ptr<ametsuchi::BlockStorage>>
makeFlatFileBlockStorage(std::string const &block_storage_dir) {
  IROHA_EXPECTED_TRY_GET_VALUE(
      flat_file,
      ametsuchi::FlatFile::create(
          block_storage_dir, log_manager->getChild("FlatFile")->getLogger()));
  return std::make_unique<ametsuchi::FlatFileBlockStorage>(
      std::move(flat_file),
      std::make_shared<shared_model::proto::ProtoBlockJsonConverter>(),
      log_manager->getChild("FlatFileBlockStorage")->getLogger());
}
class FlatBlockQuery : public BlockQueryBase {
 public:
  FlatBlockQuery(BlockStorage &block_storage, logger::LoggerPtr log)
      : BlockQueryBase(block_storage, std::move(log)){};
  std::optional<int32_t> getTxStatus(
      const shared_model::crypto::Hash &hash) override {
    assert(0);
    return {};
  }
};
expected::Result<void, std::string> restoreWsv() {
  auto log = log_manager->getChild("FlatBlockQuery")->getLogger();
  auto wsv_restorer = makeWsvRestorer();
  IROHA_EXPECTED_TRY_GET_VALUE(storage, makeStorage());
  IROHA_EXPECTED_TRY_GET_VALUE(
      flat, makeFlatFileBlockStorage(FLAGS_block_store_path));
  IROHA_EXPECTED_TRY_GET_VALUE(
      ledger_state,
      wsv_restorer->restoreWsv(
          *storage,
          false,
          std::make_shared<FlatBlockQuery>(*flat, log),
          std::make_shared<InMemoryBlockStorageFactory>()));
  assert(ledger_state);
  if (ledger_state->ledger_peers.empty()) {
    return iroha::expected::makeError<std::string>(
        "Have no peers in WSV after restoration!");
  }
  return {};
}

int main(int argc, char *argv[]) try {
  gflags::SetVersionString("1.2");
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  if (FLAGS_export != "NOEXPORT") {  // flag_was_set("export")){
    auto abs = fs::absolute(FLAGS_rocksdb_path);
    CHECK_RETURN_FMT(
        fs::exists(abs), "Path to RocksDB does not exist '{}'", abs);
    auto rdb_port = RdbConnectionInit::init(StartupWsvDataPolicy::kReuse,
                                            RocksDbOptions{FLAGS_rocksdb_path},
                                            log_manager)
                        .assumeValue();
    auto db_context_ =
        std::make_shared<ametsuchi::RocksDBContext>(std::move(rdb_port));
    RocksDbCommon rdbc{db_context_};
    return export_blocks(rdbc);
  }

  auto wsv = restoreWsv();
  if (iroha::expected::hasError(wsv))
    throw std::runtime_error(wsv.assumeError());

  return 0;
} catch (std::exception const &ex) {
  cout << "ERROR: " << ex.what() << endl;
}
