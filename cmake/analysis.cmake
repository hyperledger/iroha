# cppcheck performs analysis and saves result in build/cppcheck.xml
# expects to receive array of paths to analyzed directories relative to project root
#
# specify CPPCHECK_BIN variable to set custom path to cppcheck
# variable REPORT_DIR must be specified, otherwise default is used
if(NOT CPPCHECK_BIN)
  find_program(CPPCHECK_BIN cppcheck)
endif()

if(NOT REPORT_DIR)
  set(REPORT_DIR "${CMAKE_BINARY_DIR}")
  message(STATUS "REPORT_DIR default is ${REPORT_DIR}")
endif()

if(NOT CPPCHECK_BIN)
  message(WARNING "cppcheck can not be found in PATH. Target cppcheck is not available.")
else()
  message(STATUS "Target cppcheck enabled")
  add_custom_target(cppcheck
    COMMAND ${CPPCHECK_BIN} --xml --xml-version=2 ${CMAKE_SOURCE_DIR}
      -I ${CMAKE_SOURCE_DIR}/irohad/        # include (include_directories(...)
      -I ${CMAKE_SOURCE_DIR}/iroha-cli/     # include
      -I ${CMAKE_SOURCE_DIR}/test/          # include
      -I ${CMAKE_SOURCE_DIR}/libs/          # include
      -I ${CMAKE_SOURCE_DIR}/shared_model/  # include
      -i ${CMAKE_SOURCE_DIR}/external/      # exclude
      -i ${CMAKE_SOURCE_DIR}/schema/        # exclude
      -i ${CMAKE_BINARY_DIR}                # exclude
      --enable=all
      2> ${REPORT_DIR}/cppcheck.xml
    COMMENT "Analyzing sources with cppcheck" VERBATIM
    )
endif()

# gcovr performs coverage analysis and saves result in build/gcovr.xml
# expects to receive array of paths to analyzed directories relative to project root
#
# specify GCOVR_BIN variable to set custom path to gcovr
# variable REPORT_DIR must be specified, otherwise default is used
if(NOT GCOVR_BIN)
  find_program(GCOVR_BIN gcovr)
endif()

if(NOT REPORT_DIR)
  set(REPORT_DIR "${CMAKE_BINARY_DIR}")
  message(STATUS "REPORT_DIR default is ${REPORT_DIR}")
endif()

if(NOT GCOVR_BIN)
  message(WARNING "gcovr can not be found in PATH. Target gcovr is not available.")
else()
  message(STATUS "Target gcovr enabled")
  if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(GCOV_BACKEND "llvm-cov gcov")
  else()
    set(GCOV_BACKEND "gcov")
  endif()

  add_custom_target(gcovr
    COMMAND ${GCOVR_BIN} -s -x -r '${CMAKE_SOURCE_DIR}'
      -e '${CMAKE_SOURCE_DIR}/external/*'
      -e '${CMAKE_SOURCE_DIR}/schema/*'
      -e '${CMAKE_BINARY_DIR}/*'
      --gcov-executable='${GCOV_BACKEND}'
      -o ${REPORT_DIR}/gcovr.xml
    COMMENT "Collecting coverage data with gcovr"
    )
endif()
