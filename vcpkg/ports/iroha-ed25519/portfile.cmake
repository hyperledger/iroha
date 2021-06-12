include(vcpkg_common_functions)

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO hyperledger/iroha-ed25519
    REF 2.0.1
    SHA512 dd873b5d13d9665ae0d97204a4769f744e7d35d3e6739c1a515ea5c1a9ed6ca27c570f118e5aa009b469ae4a8574515bfced4a3ece82113439630b28e8cbfac8
    HEAD_REF master
    PATCHES 0001-Add-check-for-amd64-64-24k-pic-target.patch
)

vcpkg_configure_cmake(
    SOURCE_PATH ${SOURCE_PATH}
    PREFER_NINJA
    OPTIONS
        -DEDIMPL=ref10
        -DHASH=sha3_brainhub
        -DHUNTER_ENABLED=OFF
)

vcpkg_install_cmake()

vcpkg_fixup_cmake_targets(CONFIG_PATH lib/cmake/ed25519 TARGET_PATH share/ed25519)

file(REMOVE_RECURSE ${CURRENT_PACKAGES_DIR}/debug/include)
file(REMOVE_RECURSE ${CURRENT_PACKAGES_DIR}/debug/share)

#vcpkg_copy_pdbs()

file(INSTALL ${SOURCE_PATH}/LICENSE DESTINATION ${CURRENT_PACKAGES_DIR}/share/iroha-ed25519 RENAME copyright)
