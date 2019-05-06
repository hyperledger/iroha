.. _build-guide:

Building Iroha
==============

In this guide we will learn how to install all dependencies, required to build
Iroha and how to build it.

.. note:: You don't need to build Iroha to start using it. 
  Instead, you can download prepared Docker image from the Hub, 
  this process explained in details in the :ref:`getting-started` page of this documentation.

Preparing the Environment
-------------------------

In order to successfully build Iroha, we need to configure the environment.
There are several ways to do it and we will describe all of them.

Currently, we support Unix-like systems (we are basically targeting popular
Linux distros and macOS). If you happen to have Windows or you don't want to
spend time installing all dependencies you might want to consider using Docker
environment. Also, Windows users might consider using
`WSL <https://en.wikipedia.org/wiki/Windows_Subsystem_for_Linux>`_

.. hint:: Having troubles? Check FAQ section or communicate to us directly, in
  case you were stuck on something. We don't expect this to happen, but some
  issues with an environment are possible.

Docker
^^^^^^
.. note:: You don't need Docker to run Iroha, it is just one of the possible
  choices.

First of all, you need to install ``docker`` and ``docker-compose``. You can
read how to install it on the
`Docker's website <https://www.docker.com/community-edition/>`_

.. note:: Please, use the latest available docker daemon and docker-compose.

Then you should clone the `Iroha repository <https://github.com/hyperledger/iroha>`_
to the directory of your choice.

.. code-block:: shell

  git clone -b master https://github.com/hyperledger/iroha --depth=1

.. hint:: ``--depth=1`` option allows us to download only latest commit and
  save some time and bandwidth. If you want to get a full commit history, you
  can omit this option.

After it, you need to run the development environment. Run the
``scripts/run-iroha-dev.sh`` script:

.. code-block:: shell

  bash scripts/run-iroha-dev.sh

.. hint:: Please make sure that Docker is running before executing the script.
  macOS users could find a Docker icon in system tray, Linux user could use
  ``systemctl start docker``

After you execute this script, following things happen:

1. The script checks if you don't have containers with Iroha already running.
Successful completion finishes with the new container shell.

2. The script will download ``hyperledger/iroha:develop-build`` and ``postgres`` images.
``hyperledger/iroha:develop-build`` image contains all development dependencies and is
based on top of ``ubuntu:16.04``. ``postgres`` image is required for starting
and running Iroha.

3. Two containers are created and launched.

4. The user is attached to the interactive environment for development and
testing with ``iroha`` folder mounted from the host machine. Iroha folder
is mounted to ``/opt/iroha`` in Docker container.

Now your are ready to build Iroha! Please go to `Building Iroha` section.

Linux
^^^^^

Boost
"""""

Iroha requires Boost of at least 1.65 version.
To install Boost libraries (``libboost-all-dev``), use `current release
<http://www.boost.org/users/download/>`_ from Boost webpage. The only
dependencies are thread, system and filesystem, so use
``./bootstrap.sh --with-libraries=thread,system,filesystem`` when you are building
the project.

Other Dependencies
""""""""""""""""""

To build Iroha, you need following packages:

``build-essential`` ``automake`` ``libtool`` ``libssl-dev`` ``zlib1g-dev``
``libc6-dbg`` ``golang`` ``git`` ``tar`` ``gzip`` ``ca-certificates``
``wget`` ``curl`` ``file`` ``unzip`` ``python`` ``cmake``

Use this code to install dependencies on Debian-based Linux distro.

.. code-block:: shell

  apt-get update; \
  apt-get -y --no-install-recommends install \
  build-essential automake libtool \
  libssl-dev zlib1g-dev \
  libc6-dbg golang \
  git tar gzip ca-certificates \
  wget curl file unzip \
  python cmake

.. note::  If you are willing to actively develop Iroha and to build shared
  libraries, please consider installing the
  `latest release <https://cmake.org/download/>`_ of CMake.

macOS
^^^^^

If you want to build it from scratch and actively develop it, please use this code
to install all dependencies with Homebrew.

.. code-block:: shell

  xcode-select --install
  brew install cmake boost postgres grpc autoconf automake libtool golang soci

.. hint:: To install the Homebrew itself please run

  ``ruby -e "$(curl -fsSL https://raw.githubusercontent.com/homebrew/install/master/install)"``

Build Process
-------------

Cloning the Repository
^^^^^^^^^^^^^^^^^^^^^^
Clone the `Iroha repository <https://github.com/hyperledger/iroha>`_ to the
directory of your choice.

.. code-block:: shell

  git clone -b master https://github.com/hyperledger/iroha
  cd iroha

.. hint:: If you have installed the prerequisites with Docker, you don't need
  to clone Iroha again, because when you run ``run-iroha-dev.sh`` it attaches
  to Iroha source code folder. Feel free to edit source code files with your
  host environment and build it within docker container.


Building Iroha
^^^^^^^^^^^^^^
To build Iroha, use those commands

.. code-block:: shell

  mkdir build; cd build; cmake ..; make -j$(nproc)

Alternatively, you can use these shorthand parameters (they are not documented
though)

.. code-block:: shell

  cmake -H. -Bbuild;
  cmake --build build -- -j$(nproc)

.. note::  On macOS ``$(nproc)`` variable does not work. Check the number of
  logical cores with ``sysctl -n hw.ncpu`` and put it explicitly in the command
  above, e.g. ``cmake --build build -- -j4``

CMake Parameters
^^^^^^^^^^^^^^^^

We use CMake to build platform-dependent build files. It has numerous flags
for configuring the final build. Note that besides the listed parameters
cmake's variables can be useful as well. Also as long as this page can be
deprecated (or just not complete) you can browse custom flags via
``cmake -L``, ``cmake-gui``, or ``ccmake``.

.. hint::  You can specify parameters at the cmake configuring stage
  (e.g cmake -DTESTING=ON).

Main Parameters
"""""""""""""""

+--------------+-----------------+---------+------------------------------------------------------------------------+
| Parameter    | Possible values | Default | Description                                                            |
+==============+=================+=========+========================================================================+
| TESTING      |      ON/OFF     | ON      | Enables or disables build of the tests                                 |
+--------------+                 +---------+------------------------------------------------------------------------+
| BENCHMARKING |                 | OFF     | Enables or disables build of the Google Benchmarks library             |
+--------------+                 +---------+------------------------------------------------------------------------+
| COVERAGE     |                 | OFF     | Enables or disables lcov setting for code coverage generation          |
+--------------+-----------------+---------+------------------------------------------------------------------------+

Packaging Specific Parameters
"""""""""""""""""""""""""""""

+-----------------------+-----------------+---------+--------------------------------------------+
| Parameter             | Possible values | Default | Description                                |
+=======================+=================+=========+============================================+
| ENABLE_LIBS_PACKAGING |      ON/OFF     | ON      | Enables or disables all types of packaging |
+-----------------------+                 +---------+--------------------------------------------+
| PACKAGE_ZIP           |                 | OFF     | Enables or disables zip packaging          |
+-----------------------+                 +---------+--------------------------------------------+
| PACKAGE_TGZ           |                 | OFF     | Enables or disables tar.gz packaging       |
+-----------------------+                 +---------+--------------------------------------------+
| PACKAGE_RPM           |                 | OFF     | Enables or disables rpm packaging          |
+-----------------------+                 +---------+--------------------------------------------+
| PACKAGE_DEB           |                 | OFF     | Enables or disables deb packaging          |
+-----------------------+-----------------+---------+--------------------------------------------+

Running Tests (optional)
^^^^^^^^^^^^^^^^^^^^^^^^

After building Iroha, it is a good idea to run tests to check the operability
of the daemon. You can run tests with this code:

.. code-block:: shell

  cmake --build build --target test

Alternatively, you can run following command in the ``build`` folder

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
    -d postgres:9.5
