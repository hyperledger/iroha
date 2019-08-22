$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';

echo "Cloning and setting up vcpkg"
git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg

echo "Checkout to commit"
git -C C:\vcpkg checkout (Get-Content -Path c:\Windows\Temp\vcpkg\VCPKG_COMMIT_SHA)

echo "Apply patches to vcpkg"
foreach($file in Get-ChildItem c:\Windows\Temp\vcpkg\patches -Filter *.patch) { git -C C:\vcpkg apply $file.FullName }

echo "Run bootstrap-vcpkg.bat"
C:\vcpkg\bootstrap-vcpkg.bat

echo "Installing vcpkg packages"
C:\vcpkg\vcpkg.exe install (Get-Content -Path c:\Windows\Temp\vcpkg\VCPKG_DEPS_LIST).replace(":",":x64-windows")

echo "Installing rx-cpp"
C:\vcpkg\vcpkg.exe install (Get-Content -Path c:\Windows\Temp\vcpkg\VCPKG_HEAD_DEPS_LIST).replace(":",":x64-windows")

echo "Run vcpkg.exe integrate install"
C:\vcpkg\vcpkg.exe integrate install
