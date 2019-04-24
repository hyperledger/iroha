add_library(tbb UNKNOWN IMPORTED)

find_path(tbb_INCLUDE_DIR tbb/tbb.h)
mark_as_advanced(tbb_INCLUDE_DIR)

find_library(tbb_LIBRARY tbb)
mark_as_advanced(tbb_LIBRARY)

find_package_handle_standard_args(tbb DEFAULT_MSG
    tbb_INCLUDE_DIR
    tbb_LIBRARY
    )


set(URL https://github.com/01org/tbb.git)
set(VERSION eb6336ad29450f2a64af5123ca1b9429ff6bc11d)
set_target_description(tbb "Concurrent queue" ${URL} ${VERSION})


if (NOT tbb_FOUND OR PROFILING)
  ExternalProject_Add(01org_tbb
      GIT_REPOSITORY ${URL}
      GIT_TAG        ${VERSION}
      BUILD_IN_SOURCE 1
      BUILD_COMMAND   ${MAKE}
                      tbb_build_prefix=build
      BUILD_BYPRODUCTS ${EP_PREFIX}/src/01org_tbb/build/build_debug/${CMAKE_SHARED_LIBRARY_PREFIX}tbb_debug${CMAKE_SHARED_LIBRARY_SUFFIX}
                       ${EP_PREFIX}/src/01org_tbb/build/build_release/${CMAKE_SHARED_LIBRARY_PREFIX}tbb${CMAKE_SHARED_LIBRARY_SUFFIX}
      CONFIGURE_COMMAND "" # remove configure step
      INSTALL_COMMAND "" # remove install step
      TEST_COMMAND "" # remove test step
      UPDATE_COMMAND "" # remove update step
      )
  ExternalProject_Get_Property(01org_tbb source_dir)
  set(tbb_INCLUDE_DIR ${source_dir}/include)
  if (CMAKE_BUILD_TYPE MATCHES Debug)
    set(tbb_LIBRARY ${source_dir}/build/build_debug/${CMAKE_SHARED_LIBRARY_PREFIX}tbb_debug${CMAKE_SHARED_LIBRARY_SUFFIX})
  else()
    set(tbb_LIBRARY ${source_dir}/build/build_release/${CMAKE_SHARED_LIBRARY_PREFIX}tbb${CMAKE_SHARED_LIBRARY_SUFFIX})
  endif ()
  file(MAKE_DIRECTORY ${tbb_INCLUDE_DIR})
  link_directories(${source_dir}/build/build_debug)
  link_directories(${source_dir}/build/build_release)

  add_dependencies(tbb 01org_tbb)
endif ()

set_target_properties(tbb PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${tbb_INCLUDE_DIR}
    IMPORTED_LOCATION ${tbb_LIBRARY}
    )

if (NOT TBB_USE_GLIBCXX_VERSION AND UNIX AND NOT APPLE AND "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  # https://www.threadingbuildingblocks.org/docs/help/reference/appendices/known_issues/linux_os.html
  string(REPLACE "." "0" TBB_USE_GLIBCXX_VERSION ${CMAKE_CXX_COMPILER_VERSION})
  set_target_properties(tbb PROPERTIES
    INTERFACE_COMPILE_DEFINITIONS "TBB_USE_GLIBCXX_VERSION=${TBB_USE_GLIBCXX_VERSION}")
endif()

if(ENABLE_LIBS_PACKAGING)
  add_install_step_for_lib(${tbb_LIBRARY})
endif()
