find_program(RPMBUILD rpmbuild)
if(RPMBUILD STREQUAL "RPMBUILD-NOTFOUND")
  message(WARNING "linux-rpm can not be build without `rpmbuild`. ")
else()
  # add deb to list of generators
  list(APPEND CPACK_GENERATOR RPM)

  message(STATUS "[package] linux-rpm standalone will be packaged.")

  SET(CPACK_RPM_PACKAGE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
  SET(CPACK_RPM_PACKAGE_REQUIRES "libstdc++5")
  SET(CPACK_RPM_COMPONENT_INSTALL          ON)
endif()
