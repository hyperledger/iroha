add_library(protobuf-mutator UNKNOWN IMPORTED)

set(URL https://github.com/google/libprotobuf-mutator.git)
set(VERSION c9a1e56750a4eef6ffca95f41f79f06979056e01)
set(protomutator_LIB ${CMAKE_STATIC_LIBRARY_PREFIX}protobuf-mutator${CMAKE_STATIC_LIBRARY_SUFFIX})
set(libfuzzer_LIB ${CMAKE_STATIC_LIBRARY_PREFIX}protobuf-mutator-libfuzzer${CMAKE_STATIC_LIBRARY_SUFFIX})

externalproject_add(google_protobuf-mutator
    GIT_REPOSITORY  ${URL}
    GIT_TAG         ${VERSION}
    PATCH_COMMAND patch -p1 < ${PROJECT_SOURCE_DIR}/patch/libprotobuf-mutator.patch || true
    CMAKE_ARGS -G${CMAKE_GENERATOR} -DTESTING=OFF
    BUILD_BYPRODUCTS ${EP_PREFIX}/src/google_protobuf-mutator-build/src/${protomutator_LIB}
                     ${EP_PREFIX}/src/google_protobuf-mutator-build/src/libfuzzer/${libfuzzer_LIB}
    INSTALL_COMMAND ""
    TEST_COMMAND "" # remove test step
    UPDATE_COMMAND "" # remove update step
    )
externalproject_get_property(google_protobuf-mutator source_dir binary_dir)
set(protobuf_mutator_INCLUDE_DIR ${source_dir}/src)
set(protobuf_mutator_LIBRARY ${binary_dir}/src/${protomutator_LIB})
file(MAKE_DIRECTORY ${protobuf_mutator_INCLUDE_DIR})
include_directories(${source_dir})
link_directories(${binary_dir})

add_dependencies(protobuf-mutator google_protobuf-mutator)

set_target_properties(protobuf-mutator PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${protobuf_mutator_INCLUDE_DIR}
    INTERFACE_LINK_LIBRARIES ${protobuf_mutator_LIBRARY}
    IMPORTED_LOCATION ${binary_dir}/src/libfuzzer/${libfuzzer_LIB}
    )

if(ENABLE_LIBS_PACKAGING)
  add_install_step_for_lib(${protobuf_mutator_LIBRARY})
endif()
