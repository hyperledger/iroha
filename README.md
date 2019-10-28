# Welcome!

## What is Hyperledger Iroha?

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/960/badge)](https://bestpractices.coreinfrastructure.org/projects/960)
[![Build Status](https://jenkins.soramitsu.co.jp/buildStatus/icon?job=iroha/iroha-hyperledger/master)](https://jenkins.soramitsu.co.jp/job/iroha/job/iroha-hyperledger/job/master/)

Iroha is a straightforward distributed ledger technology (DLT), inspired by Japanese Kaizen principle — eliminate excessiveness (muri). 
Iroha has essential functionality for your asset, information and identity management needs, at the same time being an efficient and trustworthy crash fault-tolerant tool for your enterprise needs. 

Check the [overview](http://iroha.readthedocs.io/en/latest/overview.html) page of our documentation.
[Here](https://www.youtube.com/channel/UCYlK9OrZo9hvNYFuf0vrwww) is a YouTube channel where we upload meetings and explanatory videos - check them out! 

<img height="300px" src="docs/image_assets/Iroha_3_sm.png"
 alt="Iroha logo" title="Iroha" align="right" />

Iroha has the following features:
1. Creation and management of custom fungible assets, such as currencies, kilos of gold, etc.
2. Management of user accounts
3. Taxonomy of accounts based on _domains_ in the system
4. The system of rights and verification of user permissions for the execution of transactions and queries in the system
5. Validation of business rules for transactions and queries in the system
6. Multisignature transactions

Iroha is _Crash Fault Tolerant_ and has its own consensus algorithm - [YAC](https://arxiv.org/pdf/1809.00554.pdf) 

## Documentation

Our documentation is hosted at ReadTheDocs service here: [http://iroha.readthedocs.io](http://iroha.readthedocs.io).
We have documentation in several languages available and you are welcome to contribute on [POEditor website](https://poeditor.com/join/project/SFpZw7o33o)!

#### Here is the build status of different translations
<center>
 
| Build Status | **English** <br> [![Documentation Status](https://readthedocs.org/projects/iroha/badge/?version=latest)](https://iroha.readthedocs.io/en/latest/?badge=latest) </br> | **German** <br> [![Documentation Status](https://readthedocs.org/projects/iroha-de/badge/?version=master)](https://iroha.readthedocs.io/de/master/?badge=master) </br> | **Spanish** <br> [![Documentation Status](https://readthedocs.org/projects/iroha-es/badge/?version=latest)](https://iroha.readthedocs.io/es/latest/?badge=latest) </br> | **French** <br> [![Documentation Status](https://readthedocs.org/projects/iroha-fr/badge/?version=latest)](https://iroha.readthedocs.io/fr/latest/?badge=latest) </br> | **Japanese** <br> [![Documentation Status](https://readthedocs.org/projects/iroha-ja/badge/?version=latest)](https://iroha.readthedocs.io/ja/latest/?badge=latest) </br> |
|:---:|:---:|:---:|:---:|:---:|:---:|
| **Korean** <br> [![Documentation Status](https://readthedocs.org/projects/iroha-ko/badge/?version=latest)](https://iroha.readthedocs.io/ko/latest/?badge=latest) </br> | **Dutch** <br> [![Documentation Status](https://readthedocs.org/projects/iroha-nl/badge/?version=latest)](https://iroha.readthedocs.io/nl/latest/?badge=latest) </br> | **Portuguese** <br> [![Documentation Status](https://readthedocs.org/projects/iroha-pt/badge/?version=latest)](https://iroha.readthedocs.io/pt/latest/?badge=latest) </br> | **Russian** <br> [![Documentation Status](https://readthedocs.org/projects/iroha-ru/badge/?version=latest)](https://iroha.readthedocs.io/ru/latest/?badge=latest) </br> | **Ukrainian** <br> [![Documentation Status](https://readthedocs.org/projects/iroha-uk/badge/?version=latest)](https://iroha.readthedocs.io/uk/latest/?badge=latest) </br> | **Simplified Chinese** <br> [![Documentation Status](https://readthedocs.org/projects/iroha-zh/badge/?version=latest)](https://iroha.readthedocs.io/zh_CN/latest/?badge=latest) </br> |

</center>
 
### How to explore Iroha really fast?

Check [getting started](http://iroha.readthedocs.io/en/latest/getting_started/) section in your version of localized docs to start exploring the system.

### How to build Iroha?

Use [build guide](https://iroha.readthedocs.io/en/latest/build/index.html), which might be helpful if you want to modify the code and contribute.

### Is there SDK available?

Yes, in [Java](https://github.com/hyperledger/iroha-java), [Python](https://github.com/hyperledger/iroha-python), [Javascript](https://github.com/hyperledger/iroha-javascript) and [iOS](https://github.com/hyperledger/iroha-ios).

### Are there any example applications?

[Android point app](https://github.com/hyperledger/iroha-android/tree/master/iroha-android-sample) and [JavaScript wallet](https://github.com/soramitsu/iroha-wallet-js).

Also do not forget to check out [The Borsello App](https://github.com/claudiocandio/borsello) – it is a wallet for Android & iOS along with a web browser application contributed by [Claudio](https://github.com/claudiocandio).
It is based on JS Wallet but is up-to-date.

### Want to help us develop Iroha?

That's great! 
Check out [this document](https://github.com/hyperledger/iroha/blob/master/CONTRIBUTING.rst)

## Need help?

* Join [Telegram chat](https://t.me/hyperledgeriroha) or [Hyperledger RocketChat](https://chat.hyperledger.org/channel/iroha) where the maintainers, contributors and fellow users are ready to help you. 
You can also discuss your concerns and proposals and simply chat about Iroha there or in Gitter [![Join the chat at https://gitter.im/hyperledger-iroha/Lobby](https://badges.gitter.im/hyperledger-iroha/Lobby.svg)](https://gitter.im/hyperledger-iroha/Lobby)
* Submit issues and improvement suggestions via [Hyperledger Jira](https://jira.hyperledger.org/secure/CreateIssue!default.jspa) 
* Subscribe to our [mailing list](https://lists.hyperledger.org/g/iroha) to receive the latest and most important news and spread your word within Iroha community

## License

Iroha codebase is licensed under the Apache License,
Version 2.0 (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Iroha documentation files are made available under the Creative Commons
Attribution 4.0 International License (CC-BY-4.0), available at
http://creativecommons.org/licenses/by/4.0/
