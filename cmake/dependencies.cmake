find_package(PackageHandleStandardArgs)

include(ExternalProject)

set(EP_PREFIX "${PROJECT_BINARY_DIR}/external")
set_directory_properties(PROPERTIES
    EP_PREFIX ${EP_PREFIX}
    )

# Project dependencies.
find_package(Threads REQUIRED)

##########################
#         gtest          #
##########################
# testing is an option. Look at the main CMakeLists.txt for details.
if (TESTING)
  if (MSVC OR VCPKG_TOOLCHAIN)
    set(CMAKE_MODULE_PATH "")
    find_package(GTest REQUIRED CONFIG)
    add_library(gtest::gtest INTERFACE IMPORTED)
    target_link_libraries(gtest::gtest INTERFACE
        GTest::gtest
        )
    add_library(gtest::main INTERFACE IMPORTED)
    target_link_libraries(gtest::main INTERFACE
        GTest::gtest_main
        )
    add_library(gmock::gmock INTERFACE IMPORTED)
    target_link_libraries(gmock::gmock INTERFACE
        GTest::gmock
        )
    add_library(gmock::main INTERFACE IMPORTED)
    target_link_libraries(gmock::main INTERFACE
        GTest::gmock_main
        )
    set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules)
  else ()
    find_package(gtest)
  endif()
endif ()

#############################
#         speedlog          #
#############################
find_package(spdlog 1.3.1 REQUIRED)

################################
#           protobuf           #
################################
option(FIND_PROTOBUF "Try to find protobuf in system" ON)
if (MSVC OR VCPKG_TOOLCHAIN)
  find_package(Protobuf REQUIRED CONFIG)
  add_library(protobuf INTERFACE IMPORTED)
  target_link_libraries(protobuf INTERFACE
      protobuf::libprotobuf
      )

  get_target_property(Protobuf_INCLUDE_DIR protobuf::libprotobuf
    INTERFACE_INCLUDE_DIRECTORIES)

  get_target_property(Protobuf_PROTOC_EXECUTABLE protobuf::protoc
    IMPORTED_LOCATION_RELEASE)
  if(NOT EXISTS "${Protobuf_PROTOC_EXECUTABLE}")
    get_target_property(Protobuf_PROTOC_EXECUTABLE protobuf::protoc
      IMPORTED_LOCATION_DEBUG)
  endif()
  if(NOT EXISTS "${Protobuf_PROTOC_EXECUTABLE}")
    get_target_property(Protobuf_PROTOC_EXECUTABLE protobuf::protoc
      IMPORTED_LOCATION_NOCONFIG)
  endif()

  add_executable(protoc IMPORTED)
  set_target_properties(protoc PROPERTIES
      IMPORTED_LOCATION ${Protobuf_PROTOC_EXECUTABLE}
      )
else ()
  find_package(protobuf)
endif()

#########################
#         gRPC          #
#########################
option(FIND_GRPC "Try to find gRPC in system" ON)
if (MSVC OR VCPKG_TOOLCHAIN)
  find_package(gRPC REQUIRED CONFIG)

  add_library(grpc INTERFACE IMPORTED)
  target_link_libraries(grpc INTERFACE
      gRPC::grpc
      )
  add_library(grpc++ INTERFACE IMPORTED)
  target_link_libraries(grpc++ INTERFACE
      gRPC::grpc++
      )
  add_library(gpr INTERFACE IMPORTED)
  target_link_libraries(gpr INTERFACE
      gRPC::gpr
      )

  get_target_property(gRPC_CPP_PLUGIN_EXECUTABLE gRPC::grpc_cpp_plugin
    IMPORTED_LOCATION_RELEASE)
  if(NOT EXISTS "${gRPC_CPP_PLUGIN_EXECUTABLE}")
    get_target_property(gRPC_CPP_PLUGIN_EXECUTABLE gRPC::grpc_cpp_plugin
      IMPORTED_LOCATION_DEBUG)
  endif()
  if(NOT EXISTS "${gRPC_CPP_PLUGIN_EXECUTABLE}")
    get_target_property(gRPC_CPP_PLUGIN_EXECUTABLE gRPC::grpc_cpp_plugin
      IMPORTED_LOCATION_NOCONFIG)
  endif()

  add_executable(grpc_cpp_plugin IMPORTED)
  set_target_properties(grpc_cpp_plugin PROPERTIES
      IMPORTED_LOCATION ${gRPC_CPP_PLUGIN_EXECUTABLE}
      )
else ()
  find_package(grpc)
endif()

################################
#          rapidjson           #
################################
find_package(rapidjson)

##########################
#           pq           #
##########################
find_package(pq)

##########################
#          SOCI          #
##########################
find_package(soci)

################################
#            gflags            #
################################
if (MSVC)
  find_package(gflags REQUIRED CONFIG)
else ()
  find_package(gflags)
endif()

##########################
#        rx c++          #
##########################
find_package(rxcpp)

##########################
#          TBB           #
##########################
if (MSVC)
  find_package(TBB REQUIRED CONFIG)
  add_library(tbb INTERFACE IMPORTED)
  target_link_libraries(tbb INTERFACE
      TBB::tbb
      )
else ()
  find_package(tbb)
endif()

##########################
#         boost          #
##########################
find_package(Boost 1.65.0 REQUIRED
    COMPONENTS
    filesystem
    system
    thread
    )
add_library(boost INTERFACE IMPORTED)
target_link_libraries(boost INTERFACE
    Boost::boost
    Boost::filesystem
    Boost::system
    Boost::thread
    )

if(ENABLE_LIBS_PACKAGING)
  foreach (library ${Boost_LIBRARIES})
    add_install_step_for_lib(${library})
  endforeach(library)
endif()

##########################
#       benchmark        #
##########################
if(BENCHMARKING)
  find_package(benchmark)
endif()

###################################
#          ed25519/sha3           #
###################################
find_package(ed25519)

###################################
#               ursa              #
###################################
if(USE_LIBURSA)
  find_package(ursa)
endif()

###################################
#              fmt                #
###################################
find_package(fmt 5.3.0 REQUIRED CONFIG)
add_library(fmt INTERFACE IMPORTED)
target_link_libraries(fmt INTERFACE
  fmt::fmt
  )

if (USE_LIBIROHA)
  find_package(libiroha)
endif()
