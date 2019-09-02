=====================================
Deploying Iroha on Kubernetes cluster
=====================================
.. TODO: Update the guide. https://soramitsu.atlassian.net/browse/DOPS-391
.. warning:: Some parts of this guide are deprecated. Proceed at your own discretion.

By following this guide you will be able to deploy a Kubernetes cluster from scratch on AWS cloud using Terraform and Kubespray, and deploy a network of Iroha nodes on it.

Prerequisites
^^^^^^^^^^^^^
 * machine running Linux (tested on Ubuntu 16.04) or MacOS
 * Python 3.3+
 * boto3
 * Ansible 2.4+
 * *ed25519-cli* utility for key generation. Statically linked binary (for x86_64 platform) can be found in deploy/ansible/playbooks/iroha-k8s/scripts directory. You may need to `compile it yourself <https://github.com/Warchant/ed25519-cli>`__.

You do not need the items below if you already have a working Kubernetes (k8s) cluster. You can skip to `Generating Iroha configs`_ chapter.

 * Terraform 0.11.8+
 * AWS account for deploying a k8s cluster on EC2

Preparation
^^^^^^^^^^^
You need to obtain AWS key for managing resources.
We recommend to create a separate IAM user for that.
Go to your AWS console, head to "My Security Credentials" menu and create a user in "Users" section.
Assign "AmazonEC2FullAccess" and "AmazonVPCFullAccess" policies to that user.
Click "Create access key" on Security credentials tab.
Take a note for values of Access key ID and Secret key.
Set these values as environment variables in your console:

.. code-block:: shell

    export AWS_ACCESS_KEY_ID='<The value of Access key ID>'
    export AWS_SECRET_ACCESS_KEY='<The value of Secret key>'

Checkout the source tree from Github:

.. code-block:: shell

    git clone https://github.com/hyperledger/iroha && cd iroha

Setting up cloud infrastructure
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
We use Hashicorp's Terraform infrastructure management tool for automated deployment of AWS EC2 nodes in multiple regions. `Kubespray <https://github.com/kubernetes-incubator/kubespray>`__ Ansible module is used for setting up a production-grade k8s cluster.

Terraform module creates 3 AWS instances in 3 different regions: eu-west-1, eu-west-2, eu-west-3 by default. Instance type is *c5.large*. There is a separate VPC created in every region. All created VPCs are then connected using VPC peering connection. That is to create a seamless network for k8s cluster.

There are several configurable options: number of nodes in each region and its role in k8s cluster (kube-master or kube-node). They can be set either in *variables.tf* file or via environment variables (using the same variable name but prefixed with TF_VAR. See more in `Terraform docs <https://www.terraform.io/intro/getting-started/variables.html#from-environment-variables>`__). More options can be configured by tuning parameters in module's *variables.tf* file.

You must set up SSH key in *deploy/tf/k8s/variables.tf* as well. Replace public key with your own. It will added on each created EC2 instance.

Navigate to *deploy/tf/k8s* directory. Terraform needs to download required modules first:

.. code-block:: shell

    pushd deploy/tf/k8s && terraform init

Then run module execution:

.. code-block:: shell

    terraform apply && popd

Review the execution plan and type *yes* to approve. Upon completion you should see an output similar to this:

.. code-block:: shell

    Apply complete! Resources: 39 added, 0 changed, 0 destroyed.

We are now ready to deploy k8s cluster. Wait a couple of minutes before instances are initialized.

Setting up k8s cluster
^^^^^^^^^^^^^^^^^^^^^^
There is an Ansible role for setting up k8s cluster. It is an external module called Kubespray. It is stored as a submodule in Hyperledger Iroha repository. This means it needs to be initialized first:

.. code-block:: shell

    git submodule init && git submodule update

This command will download Kubespray from master repository.

Install required dependencies:

.. code-block:: shell

    pip3 install -r deploy/ansible/kubespray/requirements.txt

Proceed to actual cluster deployment. Make sure you replaced *key-file* parameter with an actual path to SSH private key that was used previously during Terraform configuration. *REGIONS* variable corresponds to default list of regions used on a previous step. Modify it accordingly in case you added or removed any. Inventory file is a Python script that returns Ansible-compatible list of hosts filtered by tag.

.. code-block:: shell

    pushd deploy/ansible && REGIONS="eu-west-1,eu-west-2,eu-west-3" VPC_VISIBILITY="public" ansible-playbook -u ubuntu -b --ssh-extra-args="-o IdentitiesOnly=yes" --key-file=<PATH_TO_SSH_KEY> -i inventory/kubespray-aws-inventory.py kubespray/cluster.yml
    popd

Upon successful completion you will have working k8s cluster.

Generating Iroha configs
^^^^^^^^^^^^^^^^^^^^^^^^
In order for Iroha to work properly it requires to generate a key pair for each node, genesis block and configuration file. This is usually a tedious and error-prone procedure, especially for a large number of nodes. We automated it with Ansible role. You can skip to `Deploying Iroha on the cluster`_ chapter if you want to quick start using default configs for k8s cluster with 4 Iroha replicas.

Generate configuration files for *N* Iroha nodes. *replicas* variable controls the number of *N*:

.. code-block:: shell

    pushd deploy/ansible && ansible-playbook -e 'replicas=7' playbooks/iroha-k8s/iroha-deploy.yml
    popd

You should find files created in *deploy/ansible/roles/iroha-k8s/files/conf*.

Deploying Iroha on the cluster
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Make sure you have configuration files in *deploy/ansible/roles/iroha-k8s/files*. Specifically, non-empty *conf* directory and *k8s-iroha.yaml* file.

There are two options for managing k8s cluster: logging into either of master node and executing commands there or configure remote management. We will cover the second option here as the first one is trivial.

In case you set up cluster using Kubespray, you can find *admin.conf* file on either of master node in */etc/kubernetes* directory. Copy this file on the control machine (the one you will be running *kubectl* command from). Make sure *server* parameter in this file points to external IP address or DNS name of a master node. Usually, there is a private IP address of the node (in case of AWS). Make sure *kubectl* utility is installed (`check out the docs <https://kubernetes.io/docs/tasks/tools/install-kubectl/>`__ for instructions).

Replace the default *kubectl* configuration:

.. code-block:: shell

    export KUBECONFIG=<PATH_TO_admin.conf>

We can now control the remote k8s cluster

*k8s-iroha.yaml* pod specification file requires the creation of a *config-map* first. This is a special resource that is mounted in the init container of each pod, and contains the configuration and genesis block files required to run Iroha.

.. code-block:: shell

    kubectl create configmap iroha-config --from-file=deploy/ansible/roles/iroha-k8s/files/conf/

Each peer will have their public and private keys stored in a Kubernetes secret which is  mounted in the init container and copied over for Iroha to use. Peers will only be able read their assigned secret when running Iroha.

.. code-block:: shell

    kubectl create -f deploy/ansible/roles/iroha-k8s/files/k8s-peer-keys.yaml

Deploy Iroha network pod specification:

.. code-block:: shell

    kubectl create -f deploy/ansible/roles/iroha-k8s/files/k8s-iroha.yaml

Wait a moment before each node downloads and starts Docker containers. Executing *kubectl get pods* command should eventually return a list of deployed pods each in *Running* state.

.. Hint:: Pods do not expose ports externally. You need to connect to Iroha instance by its hostname (iroha-0, iroha-1, etc). For that you have to have a running pod in the same network.