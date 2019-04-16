add_library(gflags UNKNOWN IMPORTED)

find_path(gflags_INCLUDE_DIR gflags/gflags.h)
mark_as_advanced(gflags_INCLUDE_DIR)

find_library(gflags_LIBRARY gflags)
mark_as_advanced(gflags_LIBRARY)

find_package_handle_standard_args(gflags DEFAULT_MSG
    gflags_INCLUDE_DIR
    gflags_LIBRARY
    )

set(URL https://github.com/gflags/gflags.git)
set(VERSION f8a0efe03aa69b3336d8e228b37d4ccb17324b88)
set_target_description(gflags "Flag parsing engine" ${URL} ${VERSION})


if (NOT gflags_FOUND)
  externalproject_add(gflags_gflags
      GIT_REPOSITORY ${URL}
      GIT_TAG        ${VERSION}
      CMAKE_ARGS
                     ${DEPS_CMAKE_ARGS}
      BUILD_BYPRODUCTS ${EP_PREFIX}/src/gflags_gflags-build/lib/libgflags.a
      INSTALL_COMMAND "" # remove install step
      TEST_COMMAND "" # remove test step
      UPDATE_COMMAND "" # remove update step
      )
  externalproject_get_property(gflags_gflags binary_dir)
  set(gflags_INCLUDE_DIR ${binary_dir}/include)
  set(gflags_LIBRARY ${binary_dir}/lib/libgflags.a)
  file(MAKE_DIRECTORY ${gflags_INCLUDE_DIR})

  add_dependencies(gflags gflags_gflags)
endif ()

set_target_properties(gflags PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${gflags_INCLUDE_DIR}
    IMPORTED_LOCATION ${gflags_LIBRARY}
    )

if (NOT MSVC)
  set_target_properties(gflags PROPERTIES
      INTERFACE_LINK_LIBRARIES "pthread"
      )
endif ()
