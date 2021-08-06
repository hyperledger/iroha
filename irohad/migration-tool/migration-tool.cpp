/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fmt/format.h>
#include <gflags/gflags.h>

#include <charconv>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>

#include "ametsuchi/impl/rocksdb_common.hpp"
#include "common/irohad_version.hpp"
#include "common/result_try.hpp"
#include "main/impl/rocksdb_connection_init.hpp"
#include "main/startup_params.hpp"   //for StartupWsvDataPolicy

#define STR(y) STRH(y)
#define STRH(x) #x
#define JSON_TRY_USER if (true)
#define JSON_CATCH_USER(exception) if (false)
//#define JSON_THROW_USER(exception)                           \
//    {std::clog << "ERROR in " << __FILE__ << ":" << __LINE__ \
//               << " (function " << __FUNCTION__ << ") - "    \
//               << (exception).what() << std::endl;           \
//     std::abort();}
#define JSON_THROW_USER(exception)                                                                  \
   {                                                                                                \
      std::clog << "ERROR in " << __FILE__ ":" STR(__LINE__) " (function " STR(__FUNCTION__) ") - " \
                << (exception).what() << std::endl;                                                 \
      std::abort();                                                                                 \
   }
#include "nlohmann/json.hpp"

using std::cout, std::cerr, std::endl;
using std::ifstream, std::ofstream;
using std::string_view;
using nlohjson = nlohmann::json;
namespace fs = std::filesystem;
using namespace iroha;
using namespace iroha::ametsuchi;

// NOLINTNEXTLINE
DEFINE_string(block_store_path, "/tmp/block_store", "Specify path to block store");
// NOLINTNEXTLINE
DEFINE_string(rocksdb_path, "rocks.db", "Specify path to RocksDB");
// NOLINTNEXTLINE
DEFINE_bool(validate, true, "validate block file format is json before write to RocksDB");
// NOLINTNEXTLINE
DEFINE_bool(force, false, "override blocks in RocksDB blockstore if exist");
// NOLINTNEXTLINE
DEFINE_string(export, "NOEXPORT", "TODO export block store to specified directory, default CWD");
// NOLINTNEXTLINE
DEFINE_bool(wsv, false, "TODO rebuild WSV, default off");

#define CHECK_RETURN(cond, ...)                                                  \
   if (!(cond)) {                                                                \
      fmt::print("ERROR in " __FILE__ ":" STR(__LINE__) " - {}\n", __VA_ARGS__); \
      return 1;                                                                  \
   }
#define CHECK_RETURN_FMT(cond, forma, ...)                      \
   if (!(cond)) {                                               \
      fmt::print("ERROR in " __FILE__ ":" STR(__LINE__) " - "); \
      fmt::print(FMT_STRING(forma), __VA_ARGS__);               \
      fmt::print("\n");                                         \
      return 1;                                                 \
   }
#define CHECK_TRY_GET_VALUE(name, ...)                                               \
   typename decltype(__VA_ARGS__)::ValueInnerType name;                              \
   if (auto _tmp_gen_var = (__VA_ARGS__); iroha::expected::hasError(_tmp_gen_var)) { \
      fmt::print("ERROR in " __FILE__ ":" STR(__LINE__) " - {}. Try --force.\n",     \
                 _tmp_gen_var.assumeError());                                        \
      return 1;                                                                      \
   } else {                                                                          \
      name = std::move(_tmp_gen_var.assumeValue());                                  \
   }

template <>
struct fmt::formatter<DbError> {
   constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }
   template <typename FormatContext>
   auto format(const DbError& e, FormatContext& ctx) {
      return format_to(ctx.out(), "{} (code:{})", e.description, e.code);
   }
};
template <>
struct fmt::formatter<fs::path> {
   constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }
   template <typename FormatContext>
   auto format(const fs::path& p, FormatContext& ctx) {
      return format_to(ctx.out(), "{}", p.string());
   }
};
template <>
struct fmt::formatter<IrohadVersion> {
   constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }
   template <typename FormatContext>
   auto format(const IrohadVersion& v, FormatContext& ctx) {
      return format_to(ctx.out(), "{}#{}#{}", v.major, v.minor, v.patch);
   }
};
template <typename O>
struct fmt::formatter<std::optional<O>> {
   constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }
   template <typename FormatContext>
   auto format(const std::optional<O>& o, FormatContext& ctx) {
      return o ? format_to(ctx.out(), "{}", *o) : format_to(ctx.out(), "_nullopt_");
   }
};

template <class O>
std::ostream& operator<<(std::ostream& os, std::optional<O> const& o) {
   return o ? (os << *o) : (os << "_nullopt_");
}

int export_blocks(RocksDbCommon& rdbc) {
   CHECK_TRY_GET_VALUE(cnt, forBlocksTotalCount(rdbc));
   assert(cnt);
   auto total = *cnt;
   while (*cnt > 0) {
      CHECK_TRY_GET_VALUE(blkstr, forBlock(rdbc, *cnt));
      assert(blkstr);
      // if(FLAGS_export.size() and FLAGS_export[0]=='/')
      auto outfilepath = fs::absolute(FLAGS_export) / fmt::format("{:016}", *cnt);
      auto ofs = ofstream(outfilepath);
      CHECK_RETURN_FMT(ofs.is_open(), "Failed to open file '{}'", outfilepath);
      ofs << blkstr;
      CHECK_RETURN_FMT(ofs.good(), "Failed to write to file '{}'", outfilepath);
      (*cnt)--;
   }
   cout << "Exported " << total << " blocks." << endl;
   return 0;
}

bool flag_was_set(auto name) { return not google::GetCommandLineFlagInfoOrDie(name).is_default; }

int main(int argc, char* argv[]) {
   gflags::SetVersionString("1.3");
   gflags::ParseCommandLineFlags(&argc, &argv, true);

   if (FLAGS_export != "NOEXPORT") {   // flag_was_set("export")){
      auto abs = fs::absolute(FLAGS_rocksdb_path);
      // cout<<"==== "<<abs<<" "<<fs::exists(abs)<<endl;
      CHECK_RETURN_FMT(fs::exists(abs), "Path to RocksDB does not exist '{}'", abs);
   }

   CHECK_TRY_GET_VALUE(rdb_port, RdbConnectionInit::init(StartupWsvDataPolicy::kReuse,
                                                         RocksDbOptions{FLAGS_rocksdb_path}, nullptr))
   auto rdb_context_ = std::make_shared<RocksDBContext>(std::move(rdb_port));
   RocksDbCommon rdbc(rdb_context_);

#if 1
   rdbc.enumerate(
       [&](auto const& it, size_t key_sz) {
          auto key = string_view(it->key().data() + key_sz, it->key().size() - key_sz);
          auto const val = string_view(it->value().data(), it->value().size());
          cout << "-- " << key << " --- " << val << endl;
          return true;
       },
       RDB_ROOT RDB_STORE);
   cout<<"------------------------------"<<endl;
#endif

#if 1
   CHECK_TRY_GET_VALUE(store_version, forStoreVersion(rdbc));
   // CHECK_RETURN(c,"Failed to get store version");
   // auto const &[major, minor, patch] = staticSplitId<3ull>(rdbc.valueBuffer(), "#");
   // CHECK_RETURN(major==1 and minor==2 and patch==0,"Wrong version");
   IrohadVersion expeted_ver{1, 2, 0};
   if (store_version.has_value()) {
      if (not FLAGS_force)
         CHECK_RETURN_FMT(store_version == expeted_ver, "Wrong version {}, expected {}", store_version,
                          expeted_ver);
   } else {
      cout << "-- blockstore does not have version.";
   }
#endif

   // FIXME find a better way to check if flag was set.
   if (not google::GetCommandLineFlagInfoOrDie("export").is_default) {   // FLAGS_export != "NOEXPORT") {
      CHECK_RETURN(export_blocks(rdbc) == 0, "Failed to export blocks.");
      return 0;
   }

   std::set<fs::path> sorted_by_name;

   for (auto& entry : fs::directory_iterator(FLAGS_block_store_path)) {
      sorted_by_name.insert(entry);
   }
   auto file_num = [](auto&& filename_str) {
      size_t n = 0;
      auto [ptr, errcode] =
          std::from_chars(filename_str.c_str(), filename_str.c_str() + filename_str.size(), n);
      return std::tuple(n, errcode);
   };
   auto [last_file_num, errcode] = file_num((*sorted_by_name.rbegin()).filename().string());
   CHECK_RETURN(errcode == std::errc(), "Filename MUST be a number");
   CHECK_RETURN_FMT(sorted_by_name.size() == last_file_num,
                    "Block store files MUST be in subsequent order - last is {} among total {}",
                    last_file_num, sorted_by_name.size())

   //FIXME somehow forBlock<kMustNotExist> on pure clean database
   auto putBlock = FLAGS_force ? forBlock<kDbOperation::kPut, kDbEntry::kCanExist>
                               : forBlock<kDbOperation::kPut, kDbEntry::kMustNotExist>;
   auto putBlocksTotalCount = FLAGS_force ? forBlocksTotalCount<kDbOperation::kPut, kDbEntry::kCanExist>
                                          : forBlocksTotalCount<kDbOperation::kPut, kDbEntry::kMustNotExist>;

   auto readFileIntoString = [](ifstream& ifs, std::string& out) {
      // todo optimize this function using fread() or posix read()
      // https://www.delftstack.com/howto/cpp/read-file-into-string-cpp/
      out = std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
   };
   auto readFileAsJson = [](ifstream& ifs, std::string& out) { out = nlohjson::parse(ifs).dump(); };
   auto file_to_string = FLAGS_validate ? readFileAsJson : readFileIntoString;

   size_t counter{};
   for (auto& filepath : sorted_by_name) {
      ++counter;
      // cout << "--- " << std::get<0>(file_num(filepath.filename().string())) << "   " << counter << endl;
      assert(std::get<0>(file_num(filepath.filename().string())) == counter);
      ifstream ifs{filepath};
      CHECK_RETURN_FMT(ifs.is_open(), "Failed to open file '{}'", filepath);
      file_to_string(ifs, rdbc.valueBuffer());
      CHECK_RETURN_FMT(!ifs.bad(), "Failed to read file '{}'", filepath);
      CHECK_TRY_GET_VALUE(blk, putBlock(rdbc, counter));
   }
   rdbc.valueBuffer() = std::to_string(sorted_by_name.size());
   CHECK_TRY_GET_VALUE(n, putBlocksTotalCount(rdbc));

#if 0
   rdbc.enumerate(
       [&](auto const& it, size_t key_sz) {
         auto key = string_view(it->key().data() + key_sz, it->key().size() - key_sz);
         auto const val = string_view(it->value().data(), it->value().size());
         cout << "-- " << key << " --- " << val << endl;
         return true;
       },
       RDB_ROOT RDB_STORE);
#endif
   rdbc.commit();
   return 0;
}
