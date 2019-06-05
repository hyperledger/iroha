## Quick Start
```
cd win/
packer build -var 'windows_password=<Strong Password>' windows-build-server.json
```

## Description
This Packer template generates AWS AMI intended to use as on-demand agent in Jenkins jobs. 
It installs Dev tools (e.g git, curl ...). A
ny extra packages are left out for the sake of keeping AMI as clean and lightweight as possible.

See available variables in `windows-build-server.json`