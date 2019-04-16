add_library(rapidjson INTERFACE IMPORTED)

find_path(rapidjson_INCLUDE_DIR rapidjson/rapidjson.h)
mark_as_advanced(rapidjson_INCLUDE_DIR)

find_package_handle_standard_args(rapidjson DEFAULT_MSG
    rapidjson_INCLUDE_DIR
    )

set(URL https://github.com/miloyip/rapidjson.git)
set(VERSION f54b0e47a08782a6131cc3d60f94d038fa6e0a51)
set_target_description(rapidjson "JSON library" ${URL} ${VERSION})

if (NOT rapidjson_FOUND)
  externalproject_add(miloyip_rapidjson
      GIT_REPOSITORY ${URL}
      GIT_TAG        ${VERSION}
      BUILD_COMMAND "" # remove build step, header only lib
      CONFIGURE_COMMAND "" # remove configure step
      INSTALL_COMMAND "" # remove install step
      TEST_COMMAND "" # remove test step
      UPDATE_COMMAND "" # remove update step
      )
  externalproject_get_property(miloyip_rapidjson source_dir)
  set(rapidjson_INCLUDE_DIR "${source_dir}/include")

  file(MAKE_DIRECTORY ${rapidjson_INCLUDE_DIR})

  add_dependencies(rapidjson miloyip_rapidjson)
endif ()

set_target_properties(rapidjson PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${rapidjson_INCLUDE_DIR}
    )
