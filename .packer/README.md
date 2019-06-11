## Quick Start
```
cd win/
packer build -var 'windows_password=<Strong Password>' -var 'security_group_id=<security_group_id>' windows-build-server.json
```
Where :

`security_group_id` - any aws security_group_id, what have RDP and WinRM ports open (3389/TCP, 5985 - 5986/TCP,)

`windows_password` - password for Administrator user which will be created in ami. 

## Description
This Packer template generates AWS AMI intended to use as on-demand agent in Jenkins jobs. 
It installs Dev tools (e.g git, curl ...).
Any extra packages are left out for the sake of keeping AMI as clean and lightweight as possible.

See available variables in `windows-build-server.json`
