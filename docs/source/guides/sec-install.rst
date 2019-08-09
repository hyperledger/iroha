Iroha installation security tips
================================
This guide is intended to secure Iroha installation. Most of the steps from this guide may seem obvious but it helps to avoid possible security problems in the future.

Physical security
^^^^^^^^^^^^^^^^^
In case the servers are located locally (physically accessible), a number of security measures have to be applied. Skip these steps if cloud hosting is used.

Establish organisational policy and/or access control system such that only authorized personnel has access to the server room.
Next, set BIOS/firmware password and configure boot order to prevent unauthorized booting from alternate media.
Make sure the bootloader is password protected if there is such a functionality. Also, it is good to have a CCTV monitoring in place.

Deployment
^^^^^^^^^^
First, verify that official repository is used for downloading `source code <https://github.com/hyperledger/iroha>`__ and `Docker images <https://hub.docker.com/r/hyperledger/iroha>`__.
Change any default passwords that are used during installation, e.g., password for connecting to postgres.
Iroha repository contains examples of private and public keys - never use it in production.
Moreover, verify that new keypairs are generated in a safe environment and only administrator has access to those keypairs (or at least minimise the number of people).
After deploying keys to Iroha peers delete private keys from the host that was used to perform deployment, i.e. private keys should reside only inside Iroha peers.
Create an encrypted backup of private keys before deleting them and limit the access to it.

Network configuration
^^^^^^^^^^^^^^^^^^^^^
Iroha listens on ports 50051 and 10001, and optionally 55552, if TLS is enabled.
Firewall settings must allow incoming/outgoing connections to/from these ports.
If possible, disable or remove any other network services with listening ports (FTP, DNS, LDAP, SMB, DHCP, NFS, SNMP, etc).
Ideally, Iroha should be as much isolated as possible in terms of networking.

You can enable TLS on torii ports if you would like to encrypt client-peer
communication.

If you don't use traffic encryption, we strongly recommend using VPN or Calico for setting up Docker overlay network, i.e. any mechanism that allows encrypting communication between peers.
Docker swarm encrypts communications by default, but remember to open necessary ports in the firewall configuration.
In case VPN is used, verify that VPN key is unavailable to other users.

If SSH is used, disable root login.
Apart from that, disable password authentication and use only keys.
It might be helpful to set up SSH log level to INFO as well.

If IPv6 is not used, it might be a good idea to disable it.

Updates
^^^^^^^
Install the latest operating system security patches and update it regularly.
If Iroha is running in Docker containers, update Docker regularly.
While being optional, it is considered a good practice to test updates on a separate server before installing to production.

Logging and monitoring
^^^^^^^^^^^^^^^^^^^^^^
- Collect and ship logs to a dedicated machine using an agent (e.g., Filebeat).
- Collect logs from all Iroha peers in a central point (e.g., Logstash).
- Transfer logging and monitoring information via an encrypted channel (e.g., https).
- Set up an authentication mechanism to prevent third parties from accessing logs.
- Set up an authentication mechanism to prevent third parties from submitting logs.
- Log all administrator access.

OS hardening
^^^^^^^^^^^^
The following steps assume Docker is used for running Iroha.

- Enable and configure Docker Content Trust.
- Allow only trusted users to control Docker daemon.
- Set up a limit for Docker container resources.

