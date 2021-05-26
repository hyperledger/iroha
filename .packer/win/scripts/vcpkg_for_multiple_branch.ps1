# This script runs vcpkg.ps1 multiple time with different iroha branches
# It is very helpful then you need setup multiple vcpkg on windows build agent,
# for example build main and develop from one ami

param(
   [string] $iroha_repo = "https://github.com/hyperledger/iroha.git",
   [array] $branches = "main"
)
$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';

$tmp_iroha_dir = "C:\Windows\Temp\iroha"

echo "Cloning  Iroha"
git clone $iroha_repo $tmp_iroha_dir

ForEach ($branch in $branches ) {
  echo "Checkout to branch: $branch"
  git -C $tmp_iroha_dir checkout $branch

  $vcpkg_path = "c:\vcpkg-$(python C:\Windows\Temp\hash.py $tmp_iroha_dir\vcpkg)"

  if (!(Test-Path $vcpkg_path)) {
    # logging
    Add-Content c:\\vcpkg-map.txt "\$(Get-Date): $branch  start build ${vcpkg_path}..."

    echo "Start vcpkg.ps1 script"
    C:\Windows\Temp\scripts\vcpkg.ps1 -vcpkg_path $vcpkg_path -iroha_vcpkg_path "${tmp_iroha_dir}\vcpkg"

    echo "vcpkg.ps1 script finished"
    Add-Content c:\\vcpkg-map.txt "\$(Get-Date): $branch finish build ${vcpkg_path}"
  }
  else { echo "$vcpkg_path already exists" }

}

echo "Remove Iroha tmp dir"
Remove-Item $tmp_iroha_dir -Recurse -Force

