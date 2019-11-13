add_library(benchmark UNKNOWN IMPORTED)

find_path(benchmark_INCLUDE_DIR benchmark/benchmark.h)
mark_as_advanced(benchmark_INCLUDE_DIR)

find_library(benchmark_LIBRARY benchmark)
mark_as_advanced(benchmark_LIBRARY)

find_package(PackageHandleStandardArgs REQUIRED)
find_package_handle_standard_args(benchmark DEFAULT_MSG
    benchmark_INCLUDE_DIR
    benchmark_LIBRARY
    )

if (NOT benchmark_FOUND)
  externalproject_add(google_benchmark
      GIT_REPOSITORY https://github.com/google/benchmark
      GIT_TAG v1.2.0
      CMAKE_ARGS
        ${DEPS_CMAKE_ARGS}
        -DBENCHMARK_ENABLE_TESTING=OFF
      INSTALL_COMMAND "" # remove install step
      TEST_COMMAND "" # remove test step
      UPDATE_COMMAND "" # remove update step
      )
  externalproject_get_property(google_benchmark source_dir binary_dir)
  set(benchmark_INCLUDE_DIR ${source_dir}/include)
  set(benchmark_LIBRARY ${binary_dir}/src/libbenchmark.a)
  file(MAKE_DIRECTORY ${benchmark_INCLUDE_DIR})

  add_dependencies(benchmark google_benchmark)
endif ()

set_target_properties(benchmark PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${benchmark_INCLUDE_DIR}
    IMPORTED_LOCATION ${benchmark_LIBRARY}
    INTERFACE_LINK_LIBRARIES "pthread"
    )
