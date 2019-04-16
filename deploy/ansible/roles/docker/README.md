Docker
=========

A role that installs Docker CE and Docker Compose including Python modules.

Requirements
------------

none

Role Variables
--------------

- variables defined by this role:

    `defaults/main.yml` list of variables:
    - `dockerVersion` - version of Docker that is going to be installed
    - `dockerComposeVersion` -  version of Docker Compose that is going to be installed


Example Playbook
----------------

```yaml
  - hosts: locals
    gather_facts: true
    roles:
      - { role: docker, tags: docker }
```
