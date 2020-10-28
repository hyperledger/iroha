find_program(DPKG dpkg)
if(DPKG STREQUAL "DPKG-NOTFOUND")
  message(WARNING "linux-deb can not be build without `dpkg`.")
else()

  # add deb to list of generators
  list(APPEND CPACK_GENERATOR DEB)

  # debian specific
  execute_process(
      COMMAND dpkg --print-architecture
      OUTPUT_VARIABLE arch_raw
  )

  remove_line_terminators(${arch_raw} arch)

  message(STATUS "[package-${arch}] linux-deb standalone will be packaged.")

  set(CPACK_DEBIAN_PACKAGE_NAME          iroha  )
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE  ${arch})  # dpkg --print-architecture
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS       ON)
  set(CPACK_DEBIAN_PACKAGE_GENERATE_SHLIBS ON)
  set(CPACK_DEBIAN_PACKAGE_GENERATE_SHLIBS_POLICY ON)
  set(CPACK_DEB_COMPONENT_INSTALL          ON)

endif()
