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
)

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
find_package(gflags 2.2.2 REQUIRED CONFIG)

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

if(ENABLE_LIBS_PACKAGING)
  foreach (library ${Boost_LIBRARIES})
    add_install_step_for_lib(${library})
  endforeach(library)
endif()

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
