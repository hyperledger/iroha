# iroha-k8s role
This role is used for generating Iroha node configuration files and keys. They are meant to be deployed in a cluster. It also contains Kubernetes service and pod definitions file that deploys Iroha cluster.

## Requirements
- Python3
- ed25519-cli for key generation. Statically linked binary (for x86_64 platform) is already bundled in iroha-k8s Ansible role. Check out [ed25519-cli](https://github.com/Warchant/ed25519-cli) repo for compilation guide for other platforms.

## Generating configs
```
ansible-playbook -e 'max_proposal_size=2000 proposal_delay=300 vote_delay=5000' --tags "iroha-k8s" ../playbooks/iroha-caliper/caliper-deploy.yml
```

This command generates and stores configuration files in `files/conf` directory under role root. In case you're deploying without using Kubernetes cluster (bare metal or simple Docker containers), you have to copy corresponding key pair on each node (nodeX.{pub,priv}). `genesis.block`, `config.sample` are identitical for each node and have to be copied as well. `entrypoint.sh` is k8s cluster-specific and can be ignored.

Ansible playbook's extra parameters are used for `config.sample` file generation.

## Deploying on k8s cluster
In order to deploy Iroha cluster using generated configs you must first create *configMap*. Being created on a single master node, it then distributed on each cluster node.
```
kubectl create configmap iroha-config --from-file=files/conf/
```

We're ready to deploy Iroha cluster:
```
kubectl create -f files/k8s-iroha.yaml
kubectl create -f files/k8s-peer-keys.yaml
```

You should see all the pods are in `Running` state after Docker images are downloaded and run on every node. Check the status with `kubectl get pods` command.
