INCLUDE(InstallRequiredSystemLibraries)

if(PACKAGE_TGZ)
  list(APPEND CPACK_GENERATOR TGZ)
endif()
if(PACKAGE_ZIP)
  list(APPEND CPACK_GENERATOR ZIP)
endif()

set(CPACK_PACKAGE_NAME                "iroha")
set(CPACK_PACKAGE_VENDOR              "Soramitsu LLC")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Iroha - simple decentralized blockchain")
SET(CPACK_PACKAGE_VENDOR              "Soramitsu LLC")
SET(CPACK_RESOURCE_FILE_LICENSE       "${CMAKE_SOURCE_DIR}/LICENSE")
SET(CPACK_PACKAGE_CONTACT             "Bogdan Vaneev <bogdan@soramitsu.co.jp>")
SET(CPACK_COMPONENTS_GROUPING         ONE_PER_GROUP)

if(NOT IROHA_VERSION)
  message(WARNING  "IROHA_VERSION is not specified, using commit hash as version")
  get_git_revision(GIT_SHA1)
  remove_line_terminators(${GIT_SHA1} GIT_SHA1)
  set(IROHA_VERSION "0x${GIT_SHA1}")
endif()

SET(CPACK_PACKAGE_VERSION ${IROHA_VERSION})
message(STATUS "[IROHA_VERSION] '${IROHA_VERSION}'")

if (CMAKE_BUILD_TYPE MATCHES Release)
  SET(CPACK_STRIP_FILES TRUE)
else()
  SET(CPACK_STRIP_FILES FALSE)
endif()

set(CPACK_COMPONENTS_ALL irohad iroha_shepherd)

if (APPLE)
  # cmake is running on mac os
  message(WARNING "On OSX only TGZ/ZIP packaging is supported")
elseif(UNIX)
  # cmake is running on unix

  if(PACKAGE_DEB)
    include(cmake/release/linux/deb/iroha.cmake)
  endif()

  if(PACKAGE_RPM)
    include(cmake/release/linux/rpm/iroha.cmake)
  endif()

else()
  message(WARNING "Packaging is supported only for APPLE and UNIX operating systems.")
endif()

INCLUDE(CPack)
