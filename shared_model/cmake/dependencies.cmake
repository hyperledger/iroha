find_package(PackageHandleStandardArgs)

include(ExternalProject)
set(EP_PREFIX "${PROJECT_BINARY_DIR}/external")
set_directory_properties(PROPERTIES
    EP_PREFIX ${EP_PREFIX}
    )

# Project dependencies.
find_package(Threads REQUIRED)

################################
#           protobuf           #
################################
option(FIND_PROTOBUF "Try to find protobuf in system" ON)
if (MSVC)
  set(CMAKE_MODULE_PATH "")
  find_package(Protobuf REQUIRED)
  add_library(protobuf INTERFACE)
  target_link_libraries(protobuf INTERFACE
      protobuf::libprotobuf
      )
  add_executable(protoc IMPORTED)
  set_target_properties(protoc PROPERTIES
      IMPORTED_LOCATION ${Protobuf_PROTOC_EXECUTABLE}
      )
  set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Modules)
else ()
  find_package(protobuf)
endif()

##########################
#         boost          #
##########################
find_package(Boost 1.65.0 REQUIRED)
add_library(boost INTERFACE IMPORTED)
set_target_properties(boost PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIRS}
    )

###################################
#          ed25519/sha3           #
###################################
find_package(ed25519)

##########################
#         gtest          #
##########################
# testing is an option. Look at the main CMakeLists.txt for details.
if (TESTING)
  if (MSVC)
    set(CMAKE_MODULE_PATH "")
    find_package(GTest REQUIRED)
    add_library(gtest INTERFACE)
    add_library(gmock INTERFACE)

    target_link_libraries(gtest INTERFACE
        GTest::GTest GTest::Main
        )
    set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Modules)
  else ()
    find_package(gtest)
  endif()
endif ()
