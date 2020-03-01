## Quick Start
```
cd win/
packer build -var 'windows_password=<Strong Password>' -var 'security_group_id=<security_group_id>' -var 'iroha_repo=https://github.com/hyperledger/iroha.git' -var 'iroha_branches=master, support/1.1.x' windows-build-server.json
```
Where :

`security_group_id` - any aws security_group_id, what have RDP and WinRM ports open (3389/TCP, 5985 - 5986/TCP,)

`windows_password` - password for Administrator user which will be created in ami. 

`iroha_repo` - Iroha repository

`iroha_branches` - branches to use as source for building vcpkg

## Description
This Packer template generates AWS AMI intended to use as on-demand agent in Jenkins jobs. 
It installs Dev tools (e.g git, curl ...).
Any extra packages are left out for the sake of keeping AMI as clean and lightweight as possible.

See available variables in `windows-build-server.json`
