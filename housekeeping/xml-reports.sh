#!/usr/bin/env bash

BUILD_DIR=/opt/iroha/build
PARALLELISM=$(nproc --all)
IROHA_HOME=$(dirname $(realpath $0))/..

cd $IROHA_HOME

# all files with source code will be here
SOURCES=$(find $PWD -type f  | egrep "\.(hpp|cpp|h|c|cc)$" | egrep -v "external")

cd $BUILD_DIR

# run vera++

if [ -z "${NO_VERACPP}" ]; then
  VERA_XML=${BUILD_DIR}/vera-report.xml
  (vera++ - -s -c ${VERA_XML}) < $SOURCES
else
  echo "[vera++] is disabled"
fi


# run cppcheck
if [ -z "${NO_CPPCHECK}" ]; then
  CPPCHECK_XML=${BUILD_DIR}/cppcheck-report.xml
  cppcheck -j${PARALLELISM} -v \
    -Ilibs -Iirohad -Iiroha-cli \
    --enable=all \
    --xml --xml-version=2 ${SOURCES} 2> ${CPPCHECK_XML}
else
  echo "[cppcheck] is disabled"
fi

# run clang-tidy
# currently sonar can not parse clang-tidy output
#run-clang-tidy-3.8.py -p $BUILD_DIR -j${PARALLELISM} -header-filter=^${BUILD_DIR}/.* 2>

# run tests, valgrind
if [ -z "${NO_VALGRIND}" ]; then
  GTEST_DIR=${BUILD_DIR}/test_bin
  for test in $(ls $GTEST_DIR); do
   VGXML=${BUILD_DIR}/valgrind-$test.xml
   # XUXML=${BUILD_DIR}/xunit-$test.xml
  
   bin=$GTEST_DIR/$test
   valgrind --xml=yes --xml-file=$VGXML \
      --leak-check=full --demangle=yes \
      $bin 
      # generate xunit files
      # disabled here, but enabled in circleci
      #--gtest_output=xml:$XUXML
  done
else
  echo "[valgrind] is disabled"
fi

# collect the coverage data 
if [ -z "${NO_GCOVR}" ]; then
  gcovr -x -r ${IROHA_HOME} > ${BUILD_DIR}/gcovr-report.xml
else
  echo "[gcovr] is disabled"
fi


# get xunit tests
if [ -z "${NO_XUNIT}" ]; then
  GTEST_DIR=$IROHA_BUILD/test_bin
  for test in $(ls $GTEST_DIR); do
    XUTEST=$IROHA_BUILD/xunit-$test.xml
    # generates build/xunit-*.xml files with reports
    $GTEST_DIR/$test --gtest_output=xml:$XUTEST
  done
fi
