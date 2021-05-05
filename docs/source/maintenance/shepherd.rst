========
Shepherd
========

Shepherd is a command line utility that helps to perform maintenance tasks with running irohad daemon.

Prerequisites
=============

To access irohad daemon, ``utility service`` has to be configured in it.
See `the configuration details <../configure/index.html#deployment-specific-parameters>`_.

Next, when invoking ``shepherd``, pass the ``--irohad`` command line argument with address and port of irohad utility service:

.. code-block:: shell

   ./shepherd --irohad 127.0.0.1:11001 <...>

Supported actions
=================

These are the things that you can do with ``shepherd`` by specifying additional command line arguments.

Graceful shutdown
^^^^^^^^^^^^^^^^^
How did you stop iroha before?
What, did you really really kill it?
Oh, please never do that again, it is not polite and nice!

.. code-block:: shell

   ./shepherd <...> --shutdown

With ``--shutdown`` argument, shepherd will politely ask Iroha to stop.

Watch it work
^^^^^^^^^^^^^
Widely considered one of the greatest pleasures is watching others work.
With shepherd you can watch Iroha working!

.. code-block:: shell

   ./shepherd <...> --status

This will subscribe for work cycle status updates.
You will get unambiguous messages when the daemon is starting, operating, terminating or has just stopped.

Other parameters
================

You can also set the logging level:

.. code-block:: shell

   ./shepherd <...> --verbosity debug <...>

Supported values are ``trace``, ``debug``, ``info``, ``warning``, ``error`` and ``critical``.
