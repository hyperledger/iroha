*******************************
Hyperledger Iroha documentation
*******************************

.. image:: ../image_assets/iroha_logo.png

.. warning::
    Please note that support for Hyperledger Iroha v1 is limited because it is no longer actively developed.

    The core team focuses on `Hyperledger Iroha v2 <https://github.com/hyperledger/iroha/tree/iroha2-dev#hyperledger-iroha>`_, a complete rewrite of Iroha in Rust.

    These versions are incompatible, so you will have to use Iroha 2 instead of Iroha 1 for the new projects.
    You can read about the differences in the `Iroha 2 documentation <https://hyperledger.github.io/iroha-2-docs/guide/iroha-2.html>`_.

.. warning::
    For secure deployment on platforms other than new Linux versions, please read `this note <deploy/index.html#security-notice>`_ first before deploying Iroha in production.

Welcome! Hyperledger Iroha is a simple blockchain platform you can use to make trusted, secure, and fast applications by bringing the power of permission-based blockchain with Crash fault-tolerant consensus. It's free, open-source, and works on Linux and Mac OS, with a variety of mobile and desktop libraries.

You can download the source code of Hyperledger Iroha and latest releases from `GitHub page <https://github.com/hyperledger/iroha>`_.

This documentation will guide you through the installation, deployment, and launch of Iroha network, and explain to you how to write an application for it. We will also see which use case scenarios are feasible now, and are going to be implemented in the future.

As Hyperledger Iroha is an open-source project, we will also cover contribution part and explain you a working process.

.. toctree::
    :maxdepth: 2
    :numbered:
    :caption: Table of contents

    overview.rst
    concepts_architecture/index.rst
    getting_started/index.rst
    integrations/index.rst
    build/index.rst
    configure/index.rst
    deploy/index.rst
    maintenance/index.rst
    develop/index.rst
    community/index.rst
    faq/index.rst
