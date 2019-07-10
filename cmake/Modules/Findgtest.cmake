add_library(gtest::gtest UNKNOWN IMPORTED)
add_library(gtest::main UNKNOWN IMPORTED)
add_library(gmock::gmock UNKNOWN IMPORTED)
add_library(gmock::main UNKNOWN IMPORTED)

find_path(gtest_INCLUDE_DIR gtest/gtest.h)
mark_as_advanced(gtest_INCLUDE_DIR)

find_library(gtest_LIBRARY gtest)
mark_as_advanced(gtest_LIBRARY)

find_library(gtest_MAIN_LIBRARY gtest_main)
mark_as_advanced(gtest_MAIN_LIBRARY)

find_path(gmock_INCLUDE_DIR gmock/gmock.h)
mark_as_advanced(gmock_INCLUDE_DIR)

find_library(gmock_LIBRARY gmock)
mark_as_advanced(gmock_LIBRARY)

find_library(gmock_MAIN_LIBRARY gmock_main)
mark_as_advanced(gmock_MAIN_LIBRARY)

find_package_handle_standard_args(gtest DEFAULT_MSG
    gtest_INCLUDE_DIR
    gtest_LIBRARY
    gtest_MAIN_LIBRARY
    gmock_INCLUDE_DIR
    gmock_LIBRARY
    gmock_MAIN_LIBRARY
    )

set(URL https://github.com/google/googletest)
set(VERSION b6cd405286ed8635ece71c72f118e659f4ade3fb) # 2019-01-04
set_target_description(gtest::gtest "Unit testing library" ${URL} ${VERSION})
set_target_description(gmock::gmock "Mocking library" ${URL} ${VERSION})

if (NOT gtest_FOUND)
  ExternalProject_Add(google_test
      GIT_REPOSITORY ${URL}
      GIT_TAG        ${VERSION}
      CMAKE_ARGS
        ${DEPS_CMAKE_ARGS}
        -Dgtest_force_shared_crt=ON
        -Dgtest_disable_pthreads=OFF
      BUILD_BYPRODUCTS ${EP_PREFIX}/src/google_test-build/googlemock/gtest/libgtest_main.a
                       ${EP_PREFIX}/src/google_test-build/googlemock/gtest/libgtest.a
                       ${EP_PREFIX}/src/google_test-build/googlemock/libgmock_main.a
                       ${EP_PREFIX}/src/google_test-build/googlemock/libgmock.a
      INSTALL_COMMAND "" # remove install step
      UPDATE_COMMAND "" # remove update step
      TEST_COMMAND "" # remove test step
      )
  ExternalProject_Get_Property(google_test source_dir binary_dir)
  set(gtest_INCLUDE_DIR ${source_dir}/googletest/include)
  set(gmock_INCLUDE_DIR ${source_dir}/googlemock/include)

  set(gtest_MAIN_LIBRARY ${binary_dir}/googlemock/gtest/libgtest_main.a)
  set(gtest_LIBRARY ${binary_dir}/googlemock/gtest/libgtest.a)

  set(gmock_MAIN_LIBRARY ${binary_dir}/googlemock/libgmock_main.a)
  set(gmock_LIBRARY ${binary_dir}/googlemock/libgmock.a)

  file(MAKE_DIRECTORY ${gtest_INCLUDE_DIR})
  file(MAKE_DIRECTORY ${gmock_INCLUDE_DIR})

  add_dependencies(gtest::gtest google_test)
  add_dependencies(gtest::main google_test)
  add_dependencies(gmock::gmock google_test)
  add_dependencies(gmock::main google_test)
endif ()

set_target_properties(gtest::gtest PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${gtest_INCLUDE_DIR}
    INTERFACE_LINK_LIBRARIES Threads::Threads
    IMPORTED_LOCATION ${gtest_LIBRARY}
    )
set_target_properties(gtest::main PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${gtest_INCLUDE_DIR}
    INTERFACE_LINK_LIBRARIES gtest::gtest
    IMPORTED_LOCATION ${gtest_MAIN_LIBRARY}
    )

set_target_properties(gmock::gmock PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${gmock_INCLUDE_DIR}
    INTERFACE_LINK_LIBRARIES Threads::Threads
    IMPORTED_LOCATION ${gmock_LIBRARY}
    )
set_target_properties(gmock::main PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${gmock_INCLUDE_DIR}
    INTERFACE_LINK_LIBRARIES gmock::gmock
    IMPORTED_LOCATION ${gmock_MAIN_LIBRARY}
    )
