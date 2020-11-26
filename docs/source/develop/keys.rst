===============
Key Pair Format
===============

Iroha uses key pairs (.pub and .priv keys) to sign transactions – every `account <../concepts_architecture/glossary.html#account>`_ has at least 1 pair.
Some accounts (if `quorum <../concepts_architecture/glossary.html#quorum>`_ is more than 1) might have more `Signatories <../concepts_architecture/glossary.html#signatory>`_ that sign transactions – and each Signatory has a pair of keys.
Cryptographic algorithms use those keys – and in Iroha we provide you with a choice – which algorithms to use.

.. note:: Check out how to create key pairs using the Python library `here <../getting_started/python-guide.html#creating-your-own-key-pairs-with-python-library>`__.

Supported Crypto Algorithms
===========================

Natively, HL Iroha uses a custom algorithm – Ed25519 with SHA-3.
These keys are supported by all versions of Iroha, including the old ones.
But as we all know, we need more universal options as well – that is why Iroha has `HL Ursa integration <../integrations/index.html#hyperledger-ursa>`_ – it is a library with different crypto algorithms, that allows to work with Iroha using more mainstream keys.
Ursa provides Iroha with support of standard Ed25519 with SHA-2 algorithm.

Public Keys
-----------

To provide easy solution that would allow using different algorithms without "breaking" backward compatibility, we introduced **multihash** format for public keys in Iroha.
You can learn more about multihash `here <https://github.com/multiformats/multihash>`__.

Generally, to use keys, different from the native SHA-3 ed25519 keys, you will need to bring them to this format:

.. code-block:: shell

	<varint key type code><varint key size in bytes><actual key bytes>


.. note:: In multihash, varints are the Most Significant Bit unsigned varints (also called base-128 varints).


If Iroha receives a standard public key of 32 bytes, it will treat is as a native Iroha key.
If it receives a multihash public key, it will treat it based on the table below.


Right now, Iroha "understands" only one multihash key format:

+------------+-----------+----------+------------------+
|Name        |Tag        |Code      |Description       |
+============+===========+==========+==================+
|ed25519-pub |key        |0xed	    |Ed25519 public key|
+------------+-----------+----------+------------------+

Examples of public keys in Iroha:

+----------------+--------+----------+-------------------------+----------------------+
| type           | code   | length   | data                    | what Iroha recognises|
+================+========+==========+=========================+======================+
| multihash key  | ED01   | 20       | 62646464c35383430b...   | ed25519/sha2         |
+----------------+--------+----------+-------------------------+----------------------+
| raw 32 byte key| --     | --       | 716fe505f69f18511a...   | ed25519/sha3         |
+----------------+--------+----------+-------------------------+----------------------+

Note that code `0xED` is encoded as `ED01` by the rules of multihash format.

Private Keys
------------

**Private keys** in Ursa are represented by concatenation of a private key and a public key – without multihash prefixes.
