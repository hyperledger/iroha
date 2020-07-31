# Iroha Special Instructions

Because Iroha Special Instructions is a very important topic in Iroha functionality we have made
this reference with detailed description of every aspect related to **ISI**.

## TL;DR

In Iroha 2.0 we have Iroha Special Instructions (inspired by commands from Iroha 1 and smart contracts in other systems).
They are provided out-of-the-box for all possible actions and contain implementations with Permissions check inside. 
But we have several Instructions for composition like ‘If’, ‘Sequence’, etc.
Therefore Iroha modules and other applications are able to compose their custom complex commands
on top of out-of-the-box Iroha Special Instructions with the help of these composition oriented instructions.
Permissions are implemented in form of assets with possibility to check action and domain this action is applied to.
