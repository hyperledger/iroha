***********
Permissions
***********

Hyperledger Iroha uses a role-based access control system to limit actions of its users.
This system greatly helps to implement use cases involving user groups having different access levels —
ranging from the weak users, who can't even receive asset transfer to the super-users.
The beauty of our permission system is that you don't have to have a super-user
in your Iroha setup or use all the possible permissions: you can create segregated and lightweight roles.

Maintenance of the system involves setting up roles and permissions, that are included in the roles.
This might be done at the initial step of system deployment — in genesis block,
or later when Iroha network is up and running, roles can be changed (if there is a role that can do that :)

This section will help you to understand permissions and give you an idea of how to create roles including certain permissions.
Each permission is provided with an example written in Python that demonstrates the way of transaction or query creation,
which require specific permission. Every example uses *commons.py* module, which listing is available at `Supplementary Sources`_ section.

*******************
List of Permissions
*******************

.. iroha_gen_permissions_index:: permissions/matrix.csv

********************
Permissions Detailed
********************

.. iroha_gen_detailed_permissions:: permissions/matrix.csv
