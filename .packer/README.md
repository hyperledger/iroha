## Quick Start
```
cd win/
PACKER_SSH_PRIVATE_KEY="\<path to SSH key\>" packer build -var 'windows_password=<>' windows-build-server.json
```

## Description
This Packer template generates AWS AMI intended to use as on-demand agent in Jenkins jobs. 
It installs Dev tools (e.g git, curl ...). A
ny extra packages are left out for the sake of keeping AMI as clean and lightweight as possible.

See available variables in `template.json`