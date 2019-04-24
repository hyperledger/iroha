add_library(ed25519 UNKNOWN IMPORTED)

find_path(ed25519_INCLUDE_DIR ed25519/ed25519.h)
mark_as_advanced(ed25519_INCLUDE_DIR)

find_library(ed25519_LIBRARY ed25519)
mark_as_advanced(ed25519_LIBRARY)

find_package_handle_standard_args(ed25519 DEFAULT_MSG
    ed25519_INCLUDE_DIR
    ed25519_LIBRARY
    )

set(URL https://github.com/hyperledger/iroha-ed25519)
set(VERSION b61a1e77af5dc458ed6a5aee395d5b22775a4917)   # v. 2.0.1
set_target_description(ed25519 "Digital signature algorithm" ${URL} ${VERSION})

if (NOT ed25519_FOUND OR PROFILING)
  externalproject_add(hyperledger_ed25519
      GIT_REPOSITORY ${URL}
      GIT_TAG        ${VERSION}
      CMAKE_ARGS
        -DTESTING=OFF
        -DBUILD=STATIC
        -DHASH=sha3_brainhub
        -DEDIMPL=ref10
        ${DEPS_CMAKE_ARGS}
      PATCH_COMMAND  ${PATCH_RANDOM}
      BUILD_BYPRODUCTS ${EP_PREFIX}/src/hyperledger_ed25519-build/${CMAKE_STATIC_LIBRARY_PREFIX}ed25519${CMAKE_STATIC_LIBRARY_SUFFIX}
      INSTALL_COMMAND "" # remove install step
      TEST_COMMAND    "" # remove test step
      UPDATE_COMMAND  "" # remove update step
      )
  externalproject_get_property(hyperledger_ed25519 binary_dir)
  externalproject_get_property(hyperledger_ed25519 source_dir)
  set(ed25519_INCLUDE_DIR ${source_dir}/include)
  set(ed25519_LIBRARY ${binary_dir}/${CMAKE_STATIC_LIBRARY_PREFIX}ed25519${CMAKE_STATIC_LIBRARY_SUFFIX})
  file(MAKE_DIRECTORY ${ed25519_INCLUDE_DIR})
  link_directories(${binary_dir})

  if(CMAKE_GENERATOR MATCHES "Visual Studio")
    set_target_properties(ed25519 PROPERTIES
      IMPORTED_LOCATION_DEBUG ${binary_dir}/Debug/${CMAKE_STATIC_LIBRARY_PREFIX}ed25519${CMAKE_STATIC_LIBRARY_SUFFIX}
      IMPORTED_LOCATION_RELEASE ${binary_dir}/Release/${CMAKE_STATIC_LIBRARY_PREFIX}ed25519${CMAKE_STATIC_LIBRARY_SUFFIX}
      )
  endif()

  add_dependencies(ed25519 hyperledger_ed25519)
endif ()

set_target_properties(ed25519 PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${ed25519_INCLUDE_DIR}
    IMPORTED_LOCATION ${ed25519_LIBRARY}
    )

if(ENABLE_LIBS_PACKAGING)
  add_install_step_for_lib(${ed25519_LIBRARY})
endif()
