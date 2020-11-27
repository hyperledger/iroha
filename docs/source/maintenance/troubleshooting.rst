===============
Troubleshooting
===============

Restore after hard shutdown
---------------------------

::

	[2020-11-27 10:40:01.764013860][th:1][warning] Irohad/Storage/FlatFileBlockStorage Error while block deserialization: Unexpected end of string. Expected a value.

	^

::

	[2020-11-25 10:36:19.993552669][C][Init]: Irohad startup failed: WSV state (height 4576773) is more recent than block storage (height 4576772).

Such messages may appear if the node crashed while using file-based block store. Please copy the missing blocks from another node, in which case you can use ``--reuse_state`` flag for fast startup, or remove the blocks starting from the empty file and recreate WSV from existing blocks.
