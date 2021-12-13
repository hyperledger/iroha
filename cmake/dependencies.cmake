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
find_package(RapidJSON 1.1.0 REQUIRED CONFIG)
add_library(RapidJSON::rapidjson INTERFACE IMPORTED)
set_target_properties(RapidJSON::rapidjson PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${RAPIDJSON_INCLUDE_DIRS}"
  INTERFACE_COMPILE_DEFINITIONS RAPIDJSON_HAS_STDSTRING=1
)

##########################
#         libpq          #
##########################
find_package(PostgreSQL REQUIRED)
function(__postgresql_find_library _name)
  find_library(${_name}
   NAMES ${ARGN}
   PATHS
     ${PostgreSQL_ROOT_DIRECTORIES}
   PATH_SUFFIXES
     lib
     ${PostgreSQL_LIBRARY_ADDITIONAL_SEARCH_SUFFIXES}
   # Help the user find it if we cannot.
   DOC "The ${PostgreSQL_LIBRARY_DIR_MESSAGE}"
  )
endfunction()
__postgresql_find_library(PostgreSQL_COMMON_LIBRARY pgcommon)
__postgresql_find_library(PostgreSQL_PORT_LIBRARY pgport)

find_package(OpenSSL REQUIRED)
target_link_libraries(PostgreSQL::PostgreSQL
  INTERFACE
  OpenSSL::SSL
  )
if(PostgreSQL_COMMON_LIBRARY)
  target_link_libraries(PostgreSQL::PostgreSQL
    INTERFACE
    ${PostgreSQL_COMMON_LIBRARY}
    )
endif()
if(PostgreSQL_PORT_LIBRARY)
  target_link_libraries(PostgreSQL::PostgreSQL
    INTERFACE
    ${PostgreSQL_PORT_LIBRARY}
    )
endif()

##########################
#          SOCI          #
##########################
find_package(soci)

################################
#            gflags            #
################################
find_package(gflags 2.2.2 REQUIRED CONFIG)

##########################
#        rx c++          #
##########################
find_package(rxcpp)

##########################
#         boost          #
##########################
find_package(Boost 1.73.0 REQUIRED
    COMPONENTS
    filesystem
    iostreams
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
#              fmt                #
###################################
find_package(fmt 5.3.0 REQUIRED CONFIG)

###################################
#         prometheus-cpp          #
###################################
find_package(prometheus-cpp REQUIRED CONFIG)
find_package(civetweb CONFIG REQUIRED)

###################################
#            rocksdb              #
###################################
find_package(RocksDB CONFIG REQUIRED)
