iOS Swift Library
-----------------

The library was created to provide convenient interface for iOS applications to communicate with Iroha blockchain including sending transactions/query, streaming transaction statuses and block commits.

Where to get
^^^^^^^^^^^^

Iroha iOS library is available through CocoaPods. To install it, simply add the following line to your Podfile:

.. code-block:: swift

    pod 'IrohaCommunication'

Also you can download the source code for the library in `its repo <https://github.com/hyperledger/iroha-ios>`__



How to use
^^^^^^^^^^

For new Iroha users we recommend to checkout `iOS example project <https://github.com/hyperledger/iroha-ios/tree/master/Example>`__.
It tries to establish connection with Iroha peer which should be also run locally on your computer to create new account and send some asset quantity to it.
To run the project, please, go through steps below:

- Follow instructions from Iroha documentation to setup and run iroha peer in Docker container.

- Clone `iroha-ios repository <https://github.com/hyperledger/iroha-ios>`__.

- cd Example directory and run pod install.

- Open IrohaCommunication.xcworkspace in XCode

- Build and Run IrohaExample target.

- Consider logs to see if the scenario completed successfully.

Feel free to experiment with example project and don't hesitate to ask any questions in Rocket.Chat.