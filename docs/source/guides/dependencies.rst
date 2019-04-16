Installing Dependencies
=======================

This page contains references and guides about installation of various tools you may need during build of different targets of Iroha project.

.. Note::
	Please note that most likely you do not need to install all the listed tools.
	Some of them are required only for building specific versions of Iroha Client Library.

Automake
--------

Installation on Ubuntu
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    sudo apt install automake
    automake --version
    # automake (GNU automake) 1.15

Bison
-----

Installation on Ubuntu
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    sudo apt install bison
    bison --version
    # bison (GNU Bison) 3.0.4

CMake
-----

Minimum required version is 3.11.4, but we recommend to install the latest available version (3.12.0 at the moment).

Installation on Ubuntu
^^^^^^^^^^^^^^^^^^^^^^

Since Ubuntu repositories contain unsuitable version of CMake, you need to install the new one manually.
Here is how to build and install CMake from sources.

.. code-block:: shell

    wget https://cmake.org/files/v3.11/cmake-3.11.4.tar.gz
    tar -xvzf cmake-3.11.4.tar.gz
    cd cmake-3.11.4/
    ./configure
    make
    sudo make install
    cmake --version
    # cmake version 3.11.4

Installation on macOS
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    brew install cmake
    cmake --version
    # cmake version 3.12.1

Git
---

Installation on Ubuntu
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    sudo apt install git
    git --version
    # git version 2.7.4

Python
------

Installation on Ubuntu
^^^^^^^^^^^^^^^^^^^^^^

For Python 2:

.. code-block:: shell

    sudo apt install python-dev
    python --version
    # Python 2.7.12


For Python 3:

.. code-block:: shell

    sudo apt install python3-dev
    python3 --version
    # Python 3.5.2

Installation on macOS
^^^^^^^^^^^^^^^^^^^^^

For Python 2:

.. code-block:: shell

    brew install python
    python --version
    # Python 2.7.12


For Python 3:

.. code-block:: shell

    brew install python3
    python3 --version
    # Python 3.5.2

PIP
---

Installation on Ubuntu
^^^^^^^^^^^^^^^^^^^^^^

For Python 2:

.. code-block:: shell

    sudo apt install python-pip
    pip --version
    # pip 8.1.1 from /usr/lib/python2.7/dist-packages (python 2.7)


For Python 3:

.. code-block:: shell

    sudo apt install python3-pip
    pip3 --version
    # pip 8.1.1 from /usr/lib/python3/dist-packages (python 3.5)

Installation on macOS
^^^^^^^^^^^^^^^^^^^^^

For Python 2:

.. code-block:: shell

    sudo easy_install pip
    pip --version
    # pip 9.0.3 from /usr/local/lib/python2.7/site-packages (python 2.7)


For Python 3:

.. code-block:: shell

    wget https://bootstrap.pypa.io/get-pip.py
    sudo python3 get-pip.py
    python3 -m pip --version
    # pip 9.0.3 from /usr/local/Cellar/python/3.6.4_4/Frameworks/Python.framework/Versions/3.6/lib/python3.6/site-packages (python 3.6)

Boost
-----

Installation on Ubuntu
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    git clone https://github.com/boostorg/boost /tmp/boost;
    (cd /tmp/boost ; git submodule update --init --recursive);
    (cd /tmp/boost ; /tmp/boost/bootstrap.sh);
    (cd /tmp/boost ; /tmp/boost/b2 headers);
    (cd /tmp/boost ; /tmp/boost/b2 cxxflags="-std=c++14" install);
    ldconfig;
    rm -rf /tmp/boost

Installation on macOS
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    brew install boost


Protobuf
--------

Installation on macOS
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    CMAKE_BUILD_TYPE="Release"
    git clone https://github.com/google/protobuf /tmp/protobuf;
    (cd /tmp/protobuf ; git checkout 106ffc04be1abf3ff3399f54ccf149815b287dd9);
    cmake \
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} \
        -Dprotobuf_BUILD_TESTS=OFF \
        -Dprotobuf_BUILD_SHARED_LIBS=ON \
        -H/tmp/protobuf/cmake \
        -B/tmp/protobuf/.build;
    cmake --build /tmp/protobuf/.build --target install;
    ldconfig;
    rm -rf /tmp/protobuf
