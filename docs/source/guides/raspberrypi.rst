Raspberry Pi 4
^^^^^^^^^^^^^^

.. note:: This guide was tested on Raspberry Pi 4 with 4 GB RAM with system Ubuntu Server 20.04. If the device doesn't have that much memory, or it is Raspberry Pi 3 extra a swap file is necessary.


Run in terminal (on RPI device):

.. code-block:: shell

  git clone --branch support/1.1.x https://github.com/hyperledger/iroha.git

Building on RPI is similar as building on Linux, but needs some extra steps.

Run in terminal:

.. code-block:: shell

  ./iroha/vcpkg/build_iroha_deps.sh
  VCPKG_FORCE_SYSTEM_BINARIES=1 ./vcpkg/vcpkg integrate install
  
After the installation of vcpkg, CMake build parameter (like ``-DCMAKE_TOOLCHAIN_FILE=/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake``) would be printed.
Copy the parameter and add to the command:

.. code-block:: shell

  cd iroha
  cmake -H. -Bbuild -DTESTING=OFF \
    -DCMAKE_TOOLCHAIN_FILE=/home/ubuntu/vcpkg/scripts/buildsystems/vcpkg.cmake
    
.. note:: For Raspberry Pi it is recommended to disable testing with flag ``-DTESTING=OFF`` because of not much resources.

After that run commands:

.. code-block:: shell

  cd build
  make
  sudo make install

Now Iroha is built and installed. If you like some extra build parameters can be found in section `Building Iroha <build.html#cmake-parameters>`_.
