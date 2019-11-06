param (
    [string]$vcpkg_path = "C:\vcpkg",
    [string]$iroha_vcpkg_path = "C:\Windows\Temp\vcpkg"
)

$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';

echo "Cloning and setting up vcpkg"
git clone https://github.com/Microsoft/vcpkg.git $vcpkg_path

echo "Checkout to commit"
git -C $vcpkg_path checkout (Get-Content -Path $iroha_vcpkg_path\VCPKG_COMMIT_SHA)

echo "Apply patches to vcpkg"
foreach($file in Get-ChildItem $iroha_vcpkg_path\patches -Filter *.patch) { git -C $vcpkg_path apply $file.FullName }

echo "Run bootstrap-vcpkg.bat"
Invoke-Expression "$vcpkg_path\bootstrap-vcpkg.bat"

echo "Installing vcpkg packages"
Invoke-Expression "$vcpkg_path\vcpkg.exe install --triplet x64-windows (Get-Content -Path $iroha_vcpkg_path\VCPKG_DEPS_LIST)"
Invoke-Expression "$vcpkg_path\vcpkg.exe install --triplet x64-windows --head (Get-Content -Path $iroha_vcpkg_path\VCPKG_HEAD_DEPS_LIST)"

echo "Run vcpkg.exe integrate install"
Invoke-Expression "$vcpkg_path\vcpkg.exe integrate install"
