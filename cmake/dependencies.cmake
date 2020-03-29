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
  find_package(GTest 1.9.0 REQUIRED CONFIG)
endif ()

#############################
#         speedlog          #
#############################
find_package(spdlog 1.3.1 REQUIRED CONFIG)

################################
#           protobuf           #
################################
find_package(Protobuf 3.8.0 REQUIRED CONFIG)

#########################
#         gRPC          #
#########################
find_package(gRPC 1.21.1 REQUIRED CONFIG)

################################
#          rapidjson           #
################################
add_library(RapidJSON::rapidjson INTERFACE IMPORTED)
if (NOT FUZZING_ONLY)
  find_package(RapidJSON 1.1.0 REQUIRED CONFIG)
  set_target_properties(RapidJSON::rapidjson PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${RAPIDJSON_INCLUDE_DIRS}"
  )
endif()

##########################
#         libpq          #
##########################
if (NOT FUZZING_ONLY)
  find_package(PostgreSQL REQUIRED)

  find_package(OpenSSL REQUIRED)
  target_link_libraries(PostgreSQL::PostgreSQL
    INTERFACE
    OpenSSL::SSL
    )
else()
  add_library(PostgreSQL::PostgreSQL UNKNOWN IMPORTED)
endif()

##########################
#          SOCI          #
##########################
if (NOT FUZZING_ONLY)
  find_package(soci)
else()
  add_library(SOCI::core UNKNOWN IMPORTED)
  add_library(SOCI::postgresql UNKNOWN IMPORTED)
endif()

################################
#            gflags            #
################################
if (NOT FUZZING_ONLY)
  find_package(gflags 2.2.2 REQUIRED CONFIG)
else()
  add_library(Gflags UNKNOWN IMPORTED)
endif()

##########################
#        rx c++          #
##########################
find_package(rxcpp)

##########################
#          TBB           #
##########################
find_package(TBB REQUIRED CONFIG)

##########################
#         boost          #
##########################
find_package(Boost 1.65.0 REQUIRED
    COMPONENTS
    filesystem
    thread
    )

##########################
#       benchmark        #
##########################
if(BENCHMARKING)
  find_package(benchmark REQUIRED CONFIG)
endif()

###################################
#          ed25519/sha3           #
###################################
find_package(ed25519 REQUIRED CONFIG)

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
