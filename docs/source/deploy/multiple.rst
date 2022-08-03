=========================================
Running multiple instances (peer network)
=========================================

In order to set up a peer network, one should follow routines, described in this section.
In this version, we support manual deployment and automated by Ansible Playbook.
Choose an option, that meets your security criteria and other needs.

Manually
--------

By manual deployment, we mean that Iroha peer network is set up without automated assistance.
It is similar to the process of running a single local instance, although the difference is the genesis block includes more than a single peer.
In order to form a block, which includes more than a single peer, or requires customization for your needs, please take a look at `:ref:`deploy_troubles` section.

Automated
---------

`iroha-swarm <https://github.com/kuvaldini/iroha-swarm>`_ produces configuration files for docker-compose to spawn a number of Iroha nodes in a one command-line. You can select database type -- RocksDB or Postgres, -- provide peer keys or use pregenerated ones. Very convenient for basic/first config file generation and for regularly changed environment (different sets of nodes).


Here is also `a guide <https://github.com/hyperledger/iroha-deploy/blob/master/ansible/roles/iroha-docker/README.md>`__ that might be outdated but could provide some helpful information.