#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(result_test result_test.cpp)
target_link_libraries(result_test
        common
        )

addtest(combine_latest_until_first_completed_test
        combine_latest_until_first_completed_test.cpp
        )
target_link_libraries(combine_latest_until_first_completed_test
        rxcpp
        )

set(LIB_FILES_TEST_DATA_DIR ${GENERATED_TEST_DATA_DIR}/lib_files)
file(MAKE_DIRECTORY ${LIB_FILES_TEST_DATA_DIR})

addtest(lib_files_test lib_files_test.cpp)
target_link_libraries(lib_files_test
        libs_files
        )
target_compile_definitions(lib_files_test
        PRIVATE
          -DPATH_TEST_DIR="${LIB_FILES_TEST_DATA_DIR}"
        )
