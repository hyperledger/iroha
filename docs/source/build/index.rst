.. _build-guide:

==============
Building Iroha
==============

In this guide we will learn how to install all dependencies, required to build
Iroha and how to actually build it.

There will be 3 steps:

#. Installing environment prerequisites

#. Installing Iroha dependencies (will be performed automatically for Docker)

#. Building Iroha

.. note:: You don't need to build Iroha to start using it.
  Instead, you can download prepared Docker image from the Hub,
  this process explained in details in the :ref:`getting-started` page of this documentation.

Prerequisites
=============

In order to successfully build Iroha, we need to configure the environment.
There are several ways to do it and we will describe all of them.

Currently, we support Unix-like systems (we are basically targeting popular
Linux distros and MacOS). If you happen to have Windows or you don't want to
spend time installing all dependencies you might want to consider using Docker
environment. Also, Windows users might consider using
`WSL <https://en.wikipedia.org/wiki/Windows_Subsystem_for_Linux>`_

Technically Iroha can be built under Windows natively in experimental mode.
This guide covers that way too.
All the stages related to native Windows build are separated from the main flow due to its significant differences.

Please choose your preferred platform below for a quick access:

    - :ref:`docker-pre`
    - :ref:`linux-pre`
    - :ref:`MacOS-pre`
    - :ref:`Windows-pre`


.. hint:: Having troubles? Check FAQ section or communicate to us directly, in
  case you were stuck on something. We don't expect this to happen, but some
  issues with an environment are possible.

.. _docker-pre:

Docker
^^^^^^

The idea of having up-to-date Docker images is to be able to run Iroha without the need to build it.
But now you have the option to run not only the ready-to-use images but also a special **Iroha Builder** within Docker, to build Iroha the way you would like it.

First of all, you need to install ``docker`` and ``docker-compose``. You can
read how to install it on the
`Docker's website <https://www.docker.com/community-edition/>`_

.. note:: Please, use the latest available docker daemon and docker-compose.

Iroha Images
""""""""""""

You can find all the Iroha Docker Images by `searching the Docker Hub <https://hub.docker.com/search?q=hyperledger%2Firoha&type=image>`_ or on `GitHub <https://github.com/orgs/hyperledger/packages?repo_name=iroha>`_.

There are currently the following images:

- ``iroha`` -- general build of Iroha 1.x; 
- ``iroha-burrow`` -- build that has Iroha 1.x with `Burrow integration <../integrations/index.html#hyperledger-burrow>`_;
- ``iroha-ursa`` -- build that has Iroha 1.x with `Ursa integration <../https://iroha.readthedocs.io/en/develop/integrations/index.html#hyperledger-ursa>`_;
- ``iroha2`` -- Iroha 2 build;
- ``iroha-builder`` -- a special image that allows you to run an Iroha builder within Docker.

.. hint:: You can read more on running the images in the `Quick Start Guide <../getting_started/index.html>`_.

Each image can be used with a respective tag indicating a branch from which the image is built.
All the available tags can be found on Docker Hub. `Here are all the tags <https://hub.docker.com/r/hyperledger/iroha/tags>`_ for ``iroha`` image.

For example, you can use ``iroha:develop`` for the development version of Iroha, or ``iroha:main`` for the release version. The same works with all the other images, too. 


Iroha Builder
"""""""""""""

Iroha builder allows you to build Iroha with `any of the parameters available <#cmake-parameters>`_ for any other platform but to do it conveniently and securely in Docker. 

Here are the steps: 

1. First of all, let's run the builder:

.. code-block:: shell

  docker run -it hyperledger/iroha-builder:latest

On this step you will start and run the image in a container in an interactive mode. You can use any available tags, default one would be ``latest``, and development tag is ``develop``. Note that you might need to perform some actions with ``sudo`` rights.

2. When you are inside the container, clone Iroha repository: 

.. code-block:: shell

  git clone https://github.com/hyperledger/iroha.git

3. When Iroha is cloned, go into Iroha folder: 

.. code-block:: shell

  cd iroha

4. Then run the script that will build all the necessary dependencies via vcpkg: 

.. code-block:: shell

  ./vcpkg/build_iroha_deps.sh $PWD/vcpkg-build



.. _linux-pre:

Linux
^^^^^

To build Iroha, you will need the following packages:

``build-essential`` ``git`` ``ca-certificates`` ``tar`` ``ninja-build`` ``curl`` ``unzip`` ``cmake``

Use this code to install environment dependencies on Debian-based Linux distro.

.. code-block:: shell

  apt-get update; \
  apt-get -y --no-install-recommends install \
  build-essential ninja-build \
  git ca-certificates tar curl unzip cmake \
  pkg-config zip

.. Important:: If you would like to use `Burrow integration <../integrations/burrow.html>`_ you will also need GO. Install it following the instructions on `the official website <https://golang.org/doc/install>`_ and then use the following command:

.. code-block:: shell

  go get github.com/golang/protobuf/protoc-gen-go

.. note::  If you are willing to actively develop Iroha and to build shared
  libraries, please consider installing the
  `latest release <https://cmake.org/download/>`_ of CMake.

RaspberryPi 4
""""""""""""""""""""""""""

To build Iroha on Raspberry Pi 4 follow the same instructions as for building Linux. 

**ATTENTION**: Iroha requires 8GiB of RAM. If your build terminates with `SIGKILL` consider creating a swap file or swap partition on the host device, or cross-compiling. 

Now you are ready to `install Iroha dependencies <#installing-dependencies-with-vcpkg-dependency-manager>`_.

.. _macos-pre:

MacOS
^^^^^

If you want to build Iroha from scratch and actively develop it, please use the following code
to install all environment dependencies with Homebrew:

.. code-block:: shell

  xcode-select --install
  brew install cmake go pkg-config coreutils ninja git gcc@9

.. hint:: To install the Homebrew itself please run

  ``ruby -e "$(curl -fsSL https://raw.githubusercontent.com/homebrew/install/master/install)"``

.. Important:: If you would like to use `Burrow integration <../integrations/burrow.html>`_ you will also need GO. Install it following the instructions on `the official website <https://golang.org/doc/install>`_ and then use the following command:

.. code-block:: shell

  go get github.com/golang/protobuf/protoc-gen-go

Now you are ready to `install Iroha dependencies <#installing-dependencies-with-vcpkg-dependency-manager>`_.

.. _windows-pre:

Windows
^^^^^^^

.. note:: All the listed commands are designed for building 64-bit version of Iroha.

Chocolatey Package Manager
""""""""""""""""""""""""""

First of all you need Chocolatey package manager installed.
Please refer `the guide <https://chocolatey.org/install>`_ for chocolatey installation.

Building the Toolset
""""""""""""""""""""

Install CMake, Git, Microsoft compilers via chocolatey being in Administrative mode of command prompt:

.. code-block:: shell

  choco install cmake git visualstudio2019-workload-vctools ninja


PostgreSQL is not a build dependency, but it is recommended to install it now for the testing later:

  .. code-block:: shell

    choco install postgresql
    # Don't forget the password you set!

Now you are ready to `install Iroha dependencies <#installing-dependencies-with-vcpkg-dependency-manager>`_.

Installing dependencies with Vcpkg Dependency Manager
=====================================================

Currently we use Vcpkg as a dependency manager for all platforms - Linux, Windows and MacOS.
We use a fixed version of Vcpkg to ensure the patches we need will work.

That stable version can only be found inside the Iroha repository, so we will need to clone Iroha.
The whole process is pretty similar for all platforms but the exact commands are slightly different.

Linux and MacOS
^^^^^^^^^^^^^^^

Run in terminal:

.. code-block:: shell

  git clone https://github.com/hyperledger/iroha.git
  cd iroha
  ./vcpkg/build_iroha_deps.sh $PWD/vcpkg-build

And that is it! You can now move to `Building Iroha <#build-process>`_ section.

Windows
^^^^^^^

Execute from Power Shell:

.. code-block:: shell

  git clone https://github.com/hyperledger/iroha.git
  cd iroha
  powershell -ExecutionPolicy ByPass -File .\.packer\win\scripts\vcpkg.ps1 .\vcpkg .\iroha\vcpkg


Great job! You can now move to `Building Iroha <#build-process>`_ section.

.. note:: If you plan to build 32-bit version of Iroha -
  you will need to install all the mentioned librares above
  prefixed with ``x86`` term instead of ``x64``.

Build Process
=============

Building Iroha
^^^^^^^^^^^^^^

1. So, after the dependencies are built, we can start building Iroha itself: 

.. code-block:: shell

  cmake -B build -DCMAKE_TOOLCHAIN_FILE=$PWD/vcpkg-build/scripts/buildsystems/vcpkg.cmake . -DCMAKE_BUILD_TYPE=RELEASE   -GNinja -DUSE_BURROW=OFF -DUSE_URSA=OFF -DTESTING=OFF -DPACKAGE_DEB=OFF

The cmake parameters such as ``-DUSE_BURROW=ON`` are exactly the parameters you can choose for your very special build. You can see the full list and description of these parameters `here <#cmake-parameters>`_.

2. Run 

.. code-block:: shell

  cmake --build ./build --target irohad

.. warning:: If you want to use tests later, instead of building `irohad` target, you need to use this:

.. code-block:: shell

  cmake --build ./build --target all 


3. Check the result by running the help: 

.. code-block:: shell

  ./build/bin/irohad --help

This step will show you all the parameters. And that is it! 

.. note:: When building on Windows do not execute this from the Power Shell. Better use x64 Native tools command prompt.

Now Iroha is built. Although, if you like, you can build it with additional parameters described below.

If you are content with the results, you can move to the next step and `run an Iroha instance <../deploy/single.html>`_. 

CMake Parameters
^^^^^^^^^^^^^^^^

We use CMake to generate platform-dependent build files.
It has numerous flags for configuring the final build.
Note that besides the listed parameters cmake's variables can be useful as well.
Also as long as this page can be deprecated (or just not complete) you can browse custom flags via ``cmake -L``, ``cmake-gui``, or ``ccmake``.

.. hint::  You can specify parameters at the cmake configuring stage
  (e.g cmake -DTESTING=ON).

Main Parameters
"""""""""""""""

+----------------------------------+-----------------+---------+------------------------------------------------------------------------+
| Parameter                        | Possible values | Default | Description                                                            |
+==================================+=================+=========+========================================================================+
| TESTING                          |      ON/OFF     | ON      | Enables or disables build of the tests                                 |
+----------------------------------+                 +---------+------------------------------------------------------------------------+
| BENCHMARKING                     |                 | OFF     | Enables or disables build of the Google Benchmarks library             |
+----------------------------------+                 +---------+------------------------------------------------------------------------+
| COVERAGE                         |                 | OFF     | Enables or disables lcov setting for code coverage generation          |
+----------------------------------+                 +---------+------------------------------------------------------------------------+
| USE_LIBURSA                      |                 | OFF     | Enables usage of the HL Ursa cryptography instead of the standard one  |
+----------------------------------+                 +---------+------------------------------------------------------------------------+
| USE_BURROW                       |                 | OFF     | Enables the HL Burrow EVM integration                                  |
+----------------------------------+-----------------+---------+------------------------------------------------------------------------+

.. note:: If you would like to use HL Ursa cryptography for your build, please install `Rust <https://www.rust-lang.org/tools/install>`_ in addition to other dependencies. Learn more about HL Ursa integration `here <../integrations/index.html#hyperledger-ursa>`_.

  If you want to use HL Burrow integration, do not forget to first install `Go <https://golang.org/doc/install>`_ and then `protoc-gen-go <https://developers.google.com/protocol-buffers/docs/reference/go-generated>`_. Learn more about `HL Burrow Integration <../integrations/index.html#hyperledger-burrow>`_.

Packaging Specific Parameters
"""""""""""""""""""""""""""""

+-----------------------+-----------------+---------+--------------------------------------------+
| Parameter             | Possible values | Default | Description                                |
+=======================+=================+=========+============================================+
| PACKAGE_ZIP           |      ON/OFF     | OFF     | Enables or disables zip packaging          |
+-----------------------+                 +---------+--------------------------------------------+
| PACKAGE_TGZ           |                 | OFF     | Enables or disables tar.gz packaging       |
+-----------------------+                 +---------+--------------------------------------------+
| PACKAGE_RPM           |                 | OFF     | Enables or disables rpm packaging          |
+-----------------------+                 +---------+--------------------------------------------+
| PACKAGE_DEB           |                 | OFF     | Enables or disables deb packaging          |
+-----------------------+-----------------+---------+--------------------------------------------+

Running Tests (optional)
^^^^^^^^^^^^^^^^^^^^^^^^
First of all, please make sure you `built Iroha correctly <#id8>`_ for the tests.

After building Iroha, it is a good idea to run tests to check the operability
of the daemon. You can run tests with this code:

.. code-block:: shell

  cmake --build build --target test

Alternatively, you can run the following command in the ``build`` folder

.. code-block:: shell

  cd build
  ctest . --output-on-failure

.. note:: Some of the tests will fail without PostgreSQL storage running,
  so if you are not using ``scripts/run-iroha-dev.sh`` script please run Docker
  container or create a local connection with following parameters:

  .. code-block:: shell

    docker run --name some-postgres \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_PASSWORD=mysecretpassword \
    -p 5432:5432 \
    -d postgres:9.5 \
    -c 'max_prepared_transactions=100'
