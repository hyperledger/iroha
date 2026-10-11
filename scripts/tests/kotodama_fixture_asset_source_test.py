"""Guard the current Kotodama v1 fixture bytes and their Rust consumers."""

from __future__ import annotations

import hashlib
import re
import unittest
from dataclasses import dataclass, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class GuardFailure(AssertionError):
    """Raised when a fixture or its Rust projection drifts."""


@dataclass(frozen=True)
class AssetSpec:
    """Expected byte projection for one versioned Kotodama fixture."""

    name: str
    digest: str
    size: int
    sentinel: bool


@dataclass(frozen=True)
class SourceSpec:
    """Current consumer fingerprint and closed fixture assets for one Rust source."""

    path: str
    skeleton_digest: str
    assets: tuple[AssetSpec, ...]


SOURCES = (
    SourceSpec(
        'crates/ivm/tests/kotodama.rs',
        '142ae3b237cba92268b1a8f199b449f9a72e9d9e94de6e2d9adf49074e8d2387',
        (
            AssetSpec('001.ko', '3b0dc428d838d7448dc26b228709fea882f41a1dbcb15fe05431df58c6d53544', 246, True),
            AssetSpec('002.ko', '24a24ebec2af2c9f2dd940362b242fe84b8d351ea1efedc618069b31df90abb1', 329, True),
            AssetSpec('003.ko', 'b14baa9b8e0440810a7dce52d52b5f36e792970f24ff2919ddb918708360ce4c', 163, True),
            AssetSpec('004.ko', '51f30026992bb722e857f4c280f599b3095ba050e965602b68d6a0dd85e42f61', 188, True),
            AssetSpec('005.ko', '6acd0f9145754daf4ee414404ec42bb5f911bb15d76b1fc63a9440c6c5c82435', 165, True),
            AssetSpec('006.ko', '80f14302dcc42236cd45cbe6df02c6d8c47a6093ac439c0f5cd09c0ee9d0f145', 206, True),
            AssetSpec('007.ko', '0dfec600c0a02ddeb07185f7f28d2ad7d3d7f89a5d09e2a18f60441e46f57ade', 766, True),
            AssetSpec('008.ko', 'f92111a778669df41d421891583bfeecc8bd044c6cfdbfd0755dc0eae317ab9e', 480, True),
            AssetSpec('009.ko', 'fc442c3cb44ed7ac66dfa853c917f406c0d0bb5d2409bd4bd112728cfcd50ecc', 206, True),
            AssetSpec('010.ko', '75e05f0d2413859281cce05dd5e71e7459d036de0b201ed9f0612fa0b09aa923', 269, True),
            AssetSpec('011.ko', '9dab22e1df9ca682af1d2e88bdeb5aff7ece147f6448fcaf0c64ec1f45c279df', 289, True),
            AssetSpec('012.ko', '9d86edb74a64d17700575b3a802c418ee8f88700c4c6f60bd0063f7a510a8f90', 497, True),
            AssetSpec('013.ko', 'b1f8ab5aff2053f39abec1674a90e81fffa561f6e2f5cfc5679f98bb0362215d', 130, True),
            AssetSpec('014.ko', 'b42e0cf7804c5e6348e12011ac399700cd1ea56daefac0b68731fab9b6ce704d', 180, True),
            AssetSpec('015.ko', '91ba073dbd11adc3296b949003de9404d8d96fb9016cc88bf876e375b94fcec2', 160, True),
            AssetSpec('016.ko', '811fc7a898f67069ff71d8903532aeb03bafd0c685962efa0b722dc636e9c073', 166, True),
            AssetSpec('017.ko', '94ed7125f30bd27b2669808da547ce3672274ffb0f75d7bde9a8634554c1920e', 160, True),
            AssetSpec('018.ko', '08e117444885d32c99bfe814e5612c9b0aed7c4d4dfb569a7662026b8699765e', 183, True),
            AssetSpec('019.ko', 'd18fe7b904d52f91a4b84dd7e867fcbfd162399a6d83d45f3044d8451103469e', 224, True),
            AssetSpec('020.ko', '466e5c5938e74a8ebd7d3f23636bb21562267b7bd06d184a23d4a050d5a1db7e', 199, True),
            AssetSpec('021.ko', '008e34d93e377643ad69cb692f823ce3fa8725bded5c322c711cc078529105f7', 147, True),
            AssetSpec('022.ko', 'b04dfd519e129be54448ad0f1db74d90595604633396374fa7534d039149d261', 251, True),
            AssetSpec('023.ko', '78229f755f5df8855070a669ad310fa182b84ba5ce7a334bb866ce4b4a194bf9', 386, True),
            AssetSpec('024.ko', '12232c2f7301b94e35599943b541e39571ffc3943e504319a3989eb46cf0ffaa', 172, True),
            AssetSpec('025.ko', '8525db4882e89b98fdcb118fbbfac68be946bec94f1ac88396297f8226c80957', 748, True),
            AssetSpec('026.ko', 'd5510f5abb7f80150448005c4436d4a181f861079f22cf664a701e8c35642849', 328, True),
            AssetSpec('027.ko', 'af7edf82532e9a7b8901962c55b1f9df53bba4563c546c67d839802a138a84cc', 470, True),
            AssetSpec('028.ko', '07c8bce80706d817c3e049254d6e8f9cb91ea919d7b4fd300c957ebb26b1a1a8', 325, True),
            AssetSpec('029.ko', 'b5fed2a934b7531e36aee4926adfa6d138429bff91fede7c59222ca308d30b1f', 178, True),
            AssetSpec('030.ko', '33c80d098a383a33821c8c3c40b54d4e1372e07fe6d84fc32b9441ba20ce6a3c', 231, True),
            AssetSpec('031.ko', '9312075de32cb706fcbcd4c18eec082d3ef2cc819d9618786506dc95edd7ac9b', 214, True),
            AssetSpec('032.ko', '25a1fff3c111c70d0f47f235705a450a1d84d9aa3047cf9959b09d783729861a', 627, True),
            AssetSpec('033.ko', '64bed1640eff9adf558f82a68d2896f54a6ee5e2295e3120ad7a6a23d92840f4', 360, True),
            AssetSpec('034.ko', '47f2f06dda9d13a75eb35f81fd890b121cd02f24b9820e0e9b9d1edddcc1b14c', 326, True),
            AssetSpec('035.ko', '3da0613849606b1cf5695ad53a441f6425a86868fe04f399df232749e49d0a52', 130, True),
            AssetSpec('036.ko', '521591eb5771f0bba533ca257b4c2721c8773edbd37eb93d22a881542476e4be', 97, True),
            AssetSpec('037.ko', '149227de4157ea5b63dc146ff495df307f3b35addfcd68a124156067f6f93c4a', 97, True),
            AssetSpec('038.ko', '129f790605313263d6188bc984f3ec21af87cbe24353923e3388ccf767b77c58', 135, True),
            AssetSpec('039.ko', '059a6be55eec0f878e6c5a34bd262d5431498e479b40a6d54661ac027cdc6825', 99, True),
            AssetSpec('040.ko', '1d98703152432503cd3a31f37fca9fbdc63ae578a1cb8eecaba71be843d6133e', 143, True),
            AssetSpec('041.ko', '62425d3edb9ebeddd582a2ddc8886552f826c138218d1bdf69cfa864aa988a9d', 96, True),
            AssetSpec('042.ko', '95b1ed8b5d96addf0d4adec3a9e1abcdc4bda6160655e38ee33245fbfb5beb1c', 134, True),
            AssetSpec('043.ko', 'ab4afbd9397dd970666ee1ef7a6a7ec7b8edf311294319f61a47a77ea471780f', 177, True),
            AssetSpec('044.ko', '393bd41567ee72e67bfc7f6d71b13d13d7c9569dfba5fb0c2b5abd5df6b172c2', 180, True),
            AssetSpec('045.ko', 'dbf13f8f1f50e7824695beaeef9b5e5753000982331e2dbbeeb43e89c0999d7f', 189, True),
            AssetSpec('046.ko', 'c0646b2148f2012fb28efccb8d61abb89514a2fd60f801bfbf86e1fe4a5c092e', 259, True),
            AssetSpec('047.ko', 'ca31f7280dbb78c5dc4d73866be7a0402eb31a080a0ba3e90f7755adf34ab91b', 284, True),
            AssetSpec('048.ko', '6b1859f00142164a8b3d18575021c2f053cc811dedd30ef5e442a0b9270ac5a5', 473, True),
            AssetSpec('049.ko', '109c959204df956f0a91912323b98646f8bab878aac8381920c7bbb41ba1e810', 264, True),
            AssetSpec('050.ko', '52cbe9051148eb1639559a108d77857eadb341ac1eb7dc6cee98fe9d1075e2c8', 512, True),
            AssetSpec('051.ko', 'a36374f25fd4a6a2cd82e086251a1afdb36213226cd75a571a81b1911d9c87e4', 447, True),
            AssetSpec('052.ko', '0e247b3fcece2f8385b4a5c467c99055f242ffaa0755933bb76c07bb213a75e9', 339, True),
            AssetSpec('053.ko', '17cca58a1f8ae78bf36b731bebbd1aba49ee0b685c2006bd00a7d2b98f06be90', 180, True),
            AssetSpec('054.ko', '63ac2faffb88e0e297290ae3446f60365641a485ab602d8a62c2bae7534e35ac', 481, True),
            AssetSpec('055.ko', '908564cf3f1cdd1be8cb5b9dfd95a220f17dd5189837df363f774e5f0453d336', 530, True),
            AssetSpec('056.ko', '6392c2dd72c66ab78d884ed26c11ce47cd837faf0049b2ba9c83cc0f7dbab016', 385, True),
            AssetSpec('057.ko', 'c67d51b9cd457287966ca3c9a350a998de9fddc7be88de09ea9afb1f049c9c47', 107, False),
            AssetSpec('058.ko', '1549b393aa5c26932e8b8b646fbf436de55287fec7c7ac32890967cd15da4b37', 168, False),
            AssetSpec('059.ko', '8bc8fd00d25bcf9e9f6b0d259bfc4543be17aa9a80b5576741d355f5932eeae9', 180, True),
            AssetSpec('060.ko', '57854702edeebb8ce9478486429951bce6c5101248570bfef1a6ea246156ecd5', 269, False),
            AssetSpec('061.ko', 'd93e6586a06c255db27d3ce38843821568c614eca875ad14e0e6a6190904364e', 199, True),
            AssetSpec('062.ko', '5bd52667ccc114a5d708729c468a39c262197354d3d5b331f94326675924eeab', 202, True),
            AssetSpec('063.ko', '28b51a80dd9b6acaf7f05b4dce2d4df4e709a85990aba0fe9125a5582297a9b2', 282, True),
            AssetSpec('064.ko', '0f53ff3bed918a58f178273fe493cf2a92be71fbd703ceb65e9ab403bad2aab6', 681, True),
            AssetSpec('065.ko', '9ebc7e2bbac7c897a9e959b528c5a18ec2342aea0829a157a0b614c16ebcf2db', 194, True),
            AssetSpec('066.ko', '15b8bc486e19a7830a5ace30720d406ef39f9157db24269b09ba1af704f3c3aa', 186, True),
            AssetSpec('067.ko', 'e9e855caf1d7182ec7d9def6b1e90ee31ceeeacdc7f98153ba9242ae234e4d1a', 168, True),
            AssetSpec('068.ko', 'ff651181676cea49b7be9b8aebee25084604e94acd62e7aee2d70166b7168552', 125, True),
            AssetSpec('069.ko', '5a4efca7c24949bcac1f0b0b5cab8841da9d40e1aa9a9bdc36d687f5a728ff1f', 220, True),
            AssetSpec('070.ko', 'b1cc15ced97ba921503f39122e09fbdac3c27877eefe1a65f328bc0adf87ac3c', 176, True),
            AssetSpec('071.ko', 'ed5f2f35e2ecf27698b9da10ecf2b5541abd5586f6b3c2395ba4766b0a011c00', 301, True),
            AssetSpec('072.ko', '480c0c822310a9e744973d69197d1e9bbe6472f6a260f54d829009c045eb5925', 182, True),
        ),
    ),
    SourceSpec(
        'crates/ivm/tests/kotodama_state_name_map_runtime.rs',
        '5f43f8f17a3979b0823c712fb6455a1d751f64e661f8ce370ad18bd6d202a50b',
        (
            AssetSpec('001.ko', '453a3d980cd5a2d3fa5d764bdfaa8861a41a81aaf34885215dcb71b34a30a907', 290, True),
            AssetSpec('002.ko', 'ad7f419edf3f569a8fef0e1c774838dd136edd213c2c2cd772c1c1e4671f497d', 417, True),
            AssetSpec('003.ko', 'c143189ded2a947f4ca1c69b6c47f163c6440bb93da77e83f875aac472bd42cf', 432, True),
            AssetSpec('004.ko', '24483800842941ec3d30e9a5036c564e7ef184bd464b589e88dc8943029c60d5', 396, True),
            AssetSpec('005.ko', '8b0d19fb39fc3e712c09e8a7e8561bf170d00256aa4dcc3bfd76fb1cf8cb64c5', 396, True),
            AssetSpec('006.ko', '74dea8f2fe019e4a4c28f689fa6b999050009c9b864b93460bfdeb428660e893', 699, True),
            AssetSpec('007.ko', 'b488ef626bbedb36f2276f1438a62fc519f81cdc3039d9e36a068dddee2d58c2', 1249, True),
            AssetSpec('008.ko', '37ed871843f32972c65264e8e9069c8da05126f3619f2e2c8e64d7c0d511ce81', 1637, True),
            AssetSpec('009.ko', '3cf099ea71481d1349dc9ad74d2ca246d4939e68789d9489ad8c95a2b95af6a9', 1500, True),
            AssetSpec('010.ko', '4a62ec9cb36637fdd0d10cd5da2e9376a401fbf0302cdb1adaaf194f179b50b6', 1180, True),
            AssetSpec('011.ko', '63e64a0231bb01d567c28326c2c237799b56ae1b46e37aad552c1bd1acc58399', 1571, True),
            AssetSpec('012.ko', 'a62df5ec30eb5b29770298b224591faa5f37ef41b662d27f5c4b5e9188db113a', 449, True),
            AssetSpec('013.ko', '21effc3032c7813343e1ab1e6779ed4cfb265b8b463e9ecb0bb1a0e5369a989a', 521, True),
            AssetSpec('014.ko', 'fdbc1096f3a580e3917cf99bd9fb20797c700c7ce42dce9f525a0be758fc5563', 216, True),
            AssetSpec('015.ko', '72cd1abf1a2f9ab88c861be74708ace89e46a68acba8b651a8a75d2e53d230e4', 213, True),
            AssetSpec('016.ko', '4aedf710ffa4ed5f9fbb0e09c56c3d0697fef554cd5242d4d19b2054987fd4b9', 765, True),
            AssetSpec('017.ko', 'b0ecd4166c45ec25f3ba4bae0b1bdc53adae306018361501c0ad7d6d8970bbec', 1500, True),
            AssetSpec('018.ko', 'dafd1f36fe1c88817a07972f980e8793d1cfca971fe3ad75ab924412d2475ed1', 616, True),
            AssetSpec('019.ko', 'fdbc1096f3a580e3917cf99bd9fb20797c700c7ce42dce9f525a0be758fc5563', 216, True),
            AssetSpec('020.ko', 'acacec7f2efb4782667a5ff03fde8d86d0e4b48fa65f80b5ea9fc0628105c1d8', 355, True),
            AssetSpec('021.ko', '5e2d78af51f24edb128469e9e309368139280884f5cac2d59de3fc9f2e6fff8d', 415, True),
            AssetSpec('022.ko', 'b0192da3c14cd53dfb1d3a14880880619245224ec4eb2b354c465baa4dbf5af9', 242, True),
            AssetSpec('023.ko', '3eee40a354f854f0e21020587c561444fa66984919840224d630f9a90c17f8bb', 336, True),
            AssetSpec('024.ko', '3225aa462981f7bcc41864d7327fd3b500a6cc68331415d7556eec8bfa2ad703', 592, True),
            AssetSpec('025.ko', 'de456575b9cc26f7f9c0b9cd680048eb26329ac687b2a793ed39ffce94b32c5a', 417, True),
            AssetSpec('026.ko', 'abd69e5c4fcf114dc8871857d78c8cbde04066673a6b7e25d2f772d5898dc530', 540, True),
            AssetSpec('027.ko', 'ae91869a24dd57d749866f0722c5cd189d5e3765c8cf971c66864ac862295254', 436, True),
            AssetSpec('028.ko', '323d89a542c618e784e75229f9524b626d34b910157d0c51ecc039807b21045e', 530, True),
            AssetSpec('029.ko', 'c41bb6cd11f48ae0fbc285525c9caaf5226f79cb7ceb648e07bb232d76bb2d06', 1251, True),
        ),
    ),
    SourceSpec(
        'crates/ivm/tests/kotodama_v1_runtime_acceptance.rs',
        'fa30b839900a5544de07d520d5e466ffe50ecc06045f884cf50697b59e839687',
        (
            AssetSpec('001.ko', 'eee436d9ed6b4b79486bb5e30248989f101c1dab2f96489830bac8022af46c3f', 334, False),
            AssetSpec('002.ko', 'c642ad27e57fbe485e00b1eb0e061c8dbfe3a32f572ec95dacfad4c35ce04936', 624, False),
            AssetSpec('003.ko', 'd5250edaecad90e81ad210db88fbba8a22abfc9ea2825f20e77e743711fc1164', 513, False),
            AssetSpec('004.ko', '405b0435bf258b7433e9f6bc7ab949296c4d5b881267a93c3cda5b04d8e82322', 1045, False),
            AssetSpec('005.ko', '29770f487a13433e26aba38fda4d13855a692893bdfaf9edb759b95e994d2e0d', 920, False),
            AssetSpec('006.ko', 'a1db1006d0daad6fd892cbb8db5eb0698f1c6cba1ca11e11b047d856529495e0', 1429, False),
            AssetSpec('007.ko', '92669ad1d37b056ea4533aacf116fdeebe59298ef862f3b06606fd787cc46258', 237, False),
            AssetSpec('008.ko', '445d9b73fae92e0a396c5d4ba319967178045887309175299e0e8e5c029e7025', 222, False),
            AssetSpec('009.ko', 'b3cccb12480ac587d5a7daebafbdff4feb45cf3f7bd8161251f9716e3e29e9b5', 437, False),
            AssetSpec('010.ko', '3649db07712c82818e5bad255d2bc7aae43a3a3a16a30bbd481f041c0df221ae', 251, False),
            AssetSpec('011.ko', '0f5d1d0762c7973a32fd66f8ad315987c688f87beb0a3982b84dc81dbb3e075d', 1087, False),
            AssetSpec('012.ko', 'e61bddc1f5d3580212abb94017f966bdb34663411acfbe7ecdd5bb8f782ef28b', 277, False),
            AssetSpec('013.ko', '575ede166da361ff00870ea28800295e8723b862d62764d0f1e19af56d0af5cc', 997, False),
            AssetSpec('014.ko', '4d100ae9654827a5b09aa3fc5eb9e80d96c096cd836ce38bd7d8dbed67b5429f', 246, False),
            AssetSpec('015.ko', 'a1f78a6876ad122b9158f73cb7f22488eaac07cfc7f5f65b6d48559edc82dc7b', 830, False),
        ),
    ),
    SourceSpec(
        'crates/ivm/tests/kotodama_lists.rs',
        'fc1b47a335f6d847047a32752808122ee3d641ae574fb58d60254ce21bf849b3',
        (
            AssetSpec('001.ko', '8bbf76933b2161f3dbc4459140bc68aa0c9d761bc55a59c6ae371120dafb9997', 593, True),
            AssetSpec('002.ko', '5abfe3588acf4209052222acd44b7e82c767dab79827355e2533b1310dce3b58', 430, True),
            AssetSpec('003.ko', 'd6e4c12a27788488503ab80cc31739cd3465551b22ee9d1bf3aa68618fa598b0', 269, True),
            AssetSpec('004.ko', 'fe45f83b3de4caa68d27851b223203481ad48dfe51206560d8da81e70f74b755', 182, True),
            AssetSpec('005.ko', '2ec5c359c5abd8f591e3a69049a8ee0d88386e6f55f7d7fe4c2243ddd97366c2', 2850, True),
            AssetSpec('006.ko', '15b8095d001904d707a5d14f98c9a5f5218248999376f02cba27c72cf5b5fae6', 317, True),
            AssetSpec('007.ko', '0bfaa9f36fd6b6ee34c0eb21f0ca711382e008cbdb70e1b761325a93dc3e257c', 184, True),
            AssetSpec('008.ko', '7c1dbbc1329011f50350cca8a60b83042f835493443bb3a6f6d4807605174202', 2611, True),
            AssetSpec('009.ko', 'f0d4249ec60fc79988648e27d3b3bb2017d9c2517bdbc1d7706d520156141e6a', 261, True),
            AssetSpec('010.ko', 'a8975bfe7f4b9f6d7081c1842ad5ea9e3b57f8951b4a02392ad942a0f70a4483', 269, True),
            AssetSpec('011.ko', '12015f28febebaa0f67159c04285dc05c3a2bd42eb010ade73fa3bbcf46d1bec', 228, True),
        ),
    ),
    SourceSpec(
        'crates/kotodama_toolchain/src/koto_test_driver_tests.rs',
        '09a7b47cb7b460b718c8a2f66e6ec5c061a67a6a5b0fd8833b6c0207dd60ef2b',
        (
            AssetSpec('001.ko', 'e005c7a50dbd95fc718ff68174019a8313a923d497efe1eab9dbfb3f161e9d52', 892, True),
            AssetSpec('002.ko', '63961644f937f1cc2e56f76506f3578fc93067ce0da0da17203855519f13394d', 217, True),
            AssetSpec('003.ko', '622947c653a3bdd5b284ef14c3ebd69d7eab3ea48384553416dd8858a72970fa', 285, True),
            AssetSpec('004.ko', '9fc45b8cb8b97a5fe6838693b63ecc4f1c480c356b94659c836f0488492c8dfa', 187, True),
            AssetSpec('005.ko', '2b09ebbd5c41ad3cb4d16f8ea31977d434208b878982c87c4caf7d66713145fa', 251, True),
            AssetSpec('006.ko', '080477cee70499044c0d28af4431ff5e2bff1537cc26b90858df8eb9265e1db3', 243, True),
            AssetSpec('007.ko', '0751af63650077193b32850f41db8807a1c1acb3c6c087e613fcd5f59169778c', 164, True),
            AssetSpec('008.ko', '1e8d71c182215071d4038d53fa290ad0238c3c8b6bf25011ada4f37e98392a71', 113, True),
            AssetSpec('009.ko', '87bd96ab4c7f49697fc508ab69842552672ffbc834ea31b95d25da29e949d1ad', 238, True),
            AssetSpec('010.ko', '077c5e8ca8661af25c30c1d9cbd427e0be025fe4ffec7575fbf68b56058cf64a', 887, True),
            AssetSpec('011.ko', '8b4952a0d978ed0de13b4978506696a03f38c55c52d3870b04f168eb7f4286b6', 1010, True),
            AssetSpec('012.ko', '684490d955bea270990d015351bc2deb3f8d8ffbfa79b92ef07c714d2979c868', 176, True),
            AssetSpec('013.ko', '60b45e4e28acd605fe3c65391eace8ba2fd5c7004a790a44b2089dd5b465462b', 438, True),
        ),
    ),
    SourceSpec(
        'crates/kotodama_lang/tests/sugar_zero_cost.rs',
        'f32e5cd71e6ebb813853b18501695c7af5a0371373037b100011e6b7a1a89206',
        (
            AssetSpec('001.ko', 'fd4f70f9b50b326c9a1756a69ad4593828f2f3e42d5414462a628dcf95a7cc2c', 248, True),
            AssetSpec('002.ko', 'd3127d2bffa912b09940d208c52760be5e98c47aec837a1796cbe9601a2a1c2e', 403, True),
            AssetSpec('003.ko', '237c8585ec437778536bfd05a6ca3eefe56bb0519e764a278ed3933534d862b7', 238, True),
            AssetSpec('004.ko', '9845d5102fc48d40a594de8eb14e3d2374a1e82b0a5475ac012b6160c0c6d7ee', 379, True),
            AssetSpec('005.ko', '698d48ea8f52bac7c51016ada41c9fc7d0901d203d80846153ea2f6d92c93e70', 123, True),
            AssetSpec('006.ko', '513daa2983a026350ad12e3513c73d5a2dd766a3d29dbf12a02eafc7fde1a97b', 131, True),
            AssetSpec('007.ko', '99495a2fd6d4a4060663f34fb2efd93ac8500e9be333e728da3b671ff4345335', 194, True),
            AssetSpec('008.ko', '50a492f88c1a22f471166bb046fe78b41b1eef196b65f5a473d8f38e8874e8ce', 182, True),
            AssetSpec('009.ko', '2d02ae02871b0a6e8c67213963c2fd5abff69da751a6c8e537f400f7c7222e42', 231, True),
            AssetSpec('010.ko', '0758c091f16381680838c13ba3dd1e7872d806218af551a415c355f3a914cb73', 296, True),
            AssetSpec('011.ko', 'c5ae53d40342ab383949cce1afbd6ce096332e117f7d0c98cd9b3d02bd5a001c', 241, True),
            AssetSpec('012.ko', 'a748681356879c2c1958c90a14c5d8524d5670aa0d5ed4ffd13b7327b1b84270', 308, True),
            AssetSpec('013.ko', '58aefc084e6d20cb3d10de35c6b6606c0c20976dd42b00c2828093fe6a114d02', 357, True),
            AssetSpec('014.ko', 'a4826a806226e992941cf23783c6805621be015290bb57832a23e880a54db084', 458, True),
            AssetSpec('015.ko', '79aedc3927ac8ffa27a2a0f93259c43f4e345b70c103d313030cf606af5475eb', 589, True),
            AssetSpec('016.ko', 'fd47ebdf1e66324e13cc98bb9808d78d4f1153f794c8b83127bdb8e891932ddd', 693, True),
            AssetSpec('017.ko', 'a32c178d9c1705943284a86fec9fbf9e0cbb4aad1c062b2ba8501889d6402ac3', 296, True),
            AssetSpec('018.ko', '84ffb416bb97e05c923d8da4f15bc85a4e5d6755d7300d85773f4ad5e51c238d', 190, True),
        ),
    ),
    SourceSpec(
        'crates/ivm/tests/kotodama_state_aggregate_literal_runtime.rs',
        'ee26bf3753b3443e78981cae4148da75cae603aa3347164567227d2523ce4865',
        (
            AssetSpec('001.ko', '82e551d02e72a8b125a55bef9d68b4fff436fa4c46f2504d07e3be52c89cd0a4', 3003, True),
            AssetSpec('002.ko', '7df136db4866d8ecd84dcba6e90dfae6d1c225c71fa3d0acb7b71ce38ea872e1', 1475, True),
        ),
    ),
    SourceSpec(
        'crates/kotodama_lang/src/compiler/tests/staged_mint_access_hints.rs',
        'adc4c9f48070d1bd2987ffcee36dcb287f7180c75b96cf08a7e509b6daba0546',
        (
            AssetSpec('001.ko', '84c5f786e83b467f1f9799bfcd79e1c2f42e983d0207ae16bf586c8591b2c571', 3546, False),
        ),
    ),
    SourceSpec(
        'crates/ivm/tests/kotodama_state_scalar.rs',
        '4f9a6ce040059b32c553cfe198752e501b8ec6df09363dedfee1da98012e46d5',
        (
            AssetSpec('001.ko', 'a3bb0c865a5a828c574e5c8860f455fec2612db32e2bdc9c2cef51be78ac8abe', 216, True),
            AssetSpec('002.ko', '4e9c0d53aa2f5f6d04822c1438c8ffcd4592154efb7e2fb55c13741314f6c011', 776, True),
            AssetSpec('003.ko', '79aedc3927ac8ffa27a2a0f93259c43f4e345b70c103d313030cf606af5475eb', 589, True),
            AssetSpec('004.ko', 'fd47ebdf1e66324e13cc98bb9808d78d4f1153f794c8b83127bdb8e891932ddd', 693, True),
        ),
    ),
    SourceSpec(
        'crates/kotodama_lang/src/resolved.rs',
        'db7374183af896185c91a00495b268cb0afaffca9d487dc176f2fd05199e310e',
        (
            AssetSpec('001.ko', 'a15f6256b419624f839af6961586120b08958cb3886b9f7a51671471b7a85e88', 176, False),
            AssetSpec('002.ko', 'fbdce614e48b118614c6817b2ec40eaa3719125c19ec72fe332acd0d5c0e8577', 249, False),
            AssetSpec('003.ko', '9d0375a8e6a6bdeec165ee4611d26e3b54974d4f0c342ec3470643ffa775f2c2', 215, False),
            AssetSpec('004.ko', '7b0764e31e6fbe2cd284a2fa67564d9ff77273dac2a22a0968ed7685ca76f3e1', 497, False),
            AssetSpec('005.ko', 'eceba390f4dd9d44387db298d606595ee18d6f9b92b4d47f64118c2bbf7df89c', 127, False),
            AssetSpec('006.ko', 'b634a8c1d989eaabc4b6590ddff68e41edb613756c4176e12a9453de2ee88bdd', 345, False),
            AssetSpec('007.ko', '87661418f9030af2bd1e4f97bf1c2eeaddc2189d74aa3a13fffca2ace995a701', 114, False),
            AssetSpec('008.ko', '67c294ed92fb8f7cdcc7fe1b4521135833c70643f45575d7f2243e0ddf4ff98c', 209, False),
            AssetSpec('009.ko', 'e9cebaea7200fb9cfbad28f7dc410a2f99089302690f5151201660b7891994f5', 92, False),
            AssetSpec('010.ko', '82f16c53cd025ea983c18e689356356f1e6720605aceff02fe8202b08f1ef0c7', 157, False),
        ),
    ),
    SourceSpec(
        'crates/kotodama_lang/src/secret.rs',
        '8c22c23eb088e7a8bbf1d22566951ec2cc223b73d1d4d17a35385cd366670902',
        (
            AssetSpec('001.ko', '2cabbe93cb0612dc119067e16807af6d72934d1fef6cbf0b193f9fcaea6cc746', 328, True),
            AssetSpec('002.ko', '3bf686a7b1c809bc2fc16c988cba69c53b041e5e74b0fa8933aa1595fb70ca87', 246, True),
            AssetSpec('003.ko', '76ca4ca26761bda42d8b66b85d3d6f0f6a6790c0eb68e8c11f149f2f33152de3', 366, True),
            AssetSpec('004.ko', 'a0ef136bcc6e4951b8259a0d8621214534d97d4d045735641766ddfd02e6f906', 237, True),
            AssetSpec('005.ko', 'c08929360d22340031ba1276a26beb966780b53ca831c5c4d3315dd2d8403e26', 250, True),
            AssetSpec('006.ko', 'a56b35698a91a4a912bdd9a31f36c97d7c44718faddd3fd48f8f974647f490b7', 295, True),
            AssetSpec('007.ko', '139dd62355ac0f230626029115da1530fb86ef1ad164034d6cfaf120298f981d', 289, True),
            AssetSpec('008.ko', '87dae5504c5cb7f3f6c82404442c185f366b25bc83fc00a6c5f788112c57fcea', 364, True),
        ),
    ),
)

# These semantic anchors explain the reviewed Rust consumer changes instead
# of allowing their skeleton seals to be advanced as opaque digest substitutions.
# These are source contracts, not execution evidence. Table ABI and anchored AXT
# runtime behavior are qualified by the corresponding Rust integration targets.
# Current contracts select authenticated public tables, reject untyped/extra test
# arguments, and encode scalar map keys through the same state records as tuples.
SOURCE_REQUIRED_FRAGMENTS = {
    'crates/ivm/tests/kotodama.rs': (
        b'use kotodama_lang::{',
        b'common::select_kotodama_entrypoint(&mut vm, &code, case.entrypoint);',
        b'fn run_vm_result_cases(cases: &[VmResultCase]) {',
        b'common::decode_i64_return_word(&vm, 0)',
        b'fn retired_axt_handle_intrinsics_are_rejected()',
        b'"asset_handle",',
        b'"axt::use_asset_handle",',
        b'.expect_err("retired AXT pointer operation is not in V1")',
        br'Json::parse(\"{\\\"cursor\\\":1,\\\"query\\\":\\\"sc_dummy\\\"}\")',
    ),
    'crates/ivm/tests/kotodama_v1_runtime_acceptance.rs': (
        b'ivm_abi::arguments::encode_argument_record_from_json(schema, &payload)',
        b'ivm_abi::numeric_tlv::encode_int(',
        b'vm.public_call_result_word(index)',
        b'common::decode_i64_return_word(&vm, 6 + index)',
        b'.try_runtime_template()',
        b'.expect("runtime template allocation fits test host")',
        b'fn native_json_literal_and_dynamic_options_preserve_identical_tags()',
        b'"maybe": { "some": "1.25" },',
        b'"present": { "some": null },',
        b'"absent": { "none": true },',
        b'fn exact_numeric_state_survives_a_fresh_host_snapshot_roundtrip()',
        b'1606938044258990275541962092341162602522202993782792835301376',
        b'assert_eq!(writer.state_paths(), ["Rate", "Supply", "Whole"]);',
    ),
    'crates/ivm/tests/kotodama_lists.rs': (
        b'ivm_abi::arguments::encode_argument_record_from_json(schema, &payload)',
        b'use kotodama_lang::compiler::Compiler as KotodamaCompiler;',
        b'{{"index":"{index}","operation":"{operation}"}}',
    ),
    'crates/kotodama_toolchain/src/koto_test_driver_tests.rs': (
        b'vm.load_koto_test_harness(',
        b'fn typed_argument_records_are_checked_against_the_target_schema_at_compile_time()',
        b'"{ until: 12, extra: false }",',
        b'assert_eq!(diagnostic.code, "E_TEST_ARGUMENT_RECORD", "{diagnostic:?}");',
        b'WsvHost::new_with_subject(MockWorldStateView::default(), caller)',
        b'WsvHost::new_with_subject(MockWorldStateView::default(), caller.clone())',
        b'WsvHost::new_with_subject(MockWorldStateView::default(), controller.clone())',
        b'fn invocation_alias_decoding_preserves_read_deferral_before_test_failure()',
        b'let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);',
        b'assert_eq!(host.invoke_entrypoint(&mut vm, false), Err(refusal));',
        b'assert_eq!(host.last_test_error(), None);',
        b'assert_eq!(budget.reserved_bytes(), occupied);',
        b'fn multifile_suite_discovers_and_executes_included_tests_with_local_modules()',
        b'temp.write("src/unrelated.ko", "this file is deliberately invalid");',
        b'fn immutable_source_suite_uses_supplied_include_and_never_loads_ambient_file()',
        b'run_tests_structured_source_with_modules_v1(',
        b'assert_eq!(report.cases.len(), 1);',
        b'"module Math { export fn value() -> int { return 7; } }"',
    ),
    'crates/ivm/tests/kotodama_state_name_map_runtime.rs': (
        b'let key = common::encode_int_state_value(key);',
        b'use kotodama_lang::compiler::Compiler as KotodamaCompiler;',
        b'use std::str::FromStr;',
        b'WsvHost::new_with_subject(wsv, subject);',
    ),
    # The builtin registry and V1 source policy live in the kotodama_surface leaf.
    'crates/kotodama_lang/src/resolved.rs': (
        b'use kotodama_surface::builtins::Builtin;',
        b'kotodama_surface::source_policy::is_reserved_source_declaration(',
        b'included: Vec<ResolvedProgram>',
        b'original: Option<Box<ResolvedProgram>>',
        b'std::iter::once(self.original.as_deref().unwrap_or(self)).chain(self.included.iter())',
        b'pub(crate) fn with_included_sources(',
        b'self.original = Some(Box::new(self.clone()));',
        b'.map(|(source, index)| originals[source].items[*index].clone())',
        b'file.attach_sources(typed);',
        b'state.source = Some(source);',
    ),
    'crates/kotodama_lang/src/secret.rs': (
        b'use kotodama_surface::builtins::{Builtin, BuiltinAccess};',
    ),
    'crates/kotodama_lang/src/compiler/tests/staged_mint_access_hints.rs': (
        b'string_literal_temps.contains(&(func_idx, *value)),',
    ),
    # K1b: ivm no longer re-exports the Kotodama compiler; tests import kotodama_lang directly.
    'crates/ivm/tests/kotodama_state_aggregate_literal_runtime.rs': (
        b'use kotodama_lang::compiler::Compiler as KotodamaCompiler;',
    ),
    'crates/ivm/tests/kotodama_state_scalar.rs': (
        b'use kotodama_lang::compiler::Compiler as KotodamaCompiler;',
    ),
}
SOURCE_FORBIDDEN_FRAGMENTS = {
    'crates/ivm/tests/kotodama.rs': (
        b'__entrypoint_impl__',
        b'decode_i64_register(',
        b'axt::AssetHandle {',
        b'ParsedAccountId',
        br'Json::parse(\"{\\\"query\\\":\\\"sc_dummy\\\",\\\"cursor\\\":1}\")',
    ),
    'crates/ivm/tests/kotodama_v1_runtime_acceptance.rs': (
        b'ivm::encode_argument_record_from_json(',
        b'ivm::numeric_tlv::encode_int(',
        b'decode_i64_register(',
        b'vm.register(10',
        b'.runtime_template()',
    ),
    'crates/ivm/tests/kotodama_lists.rs': (
        b'ivm::encode_argument_record_from_json(',
        b'{{"operation":"{operation}","index":"{index}"}}',
    ),
    'crates/kotodama_toolchain/src/koto_test_driver_tests.rs': (
        b'mv::allocation::AllocationBudget',
        b'load_koto_test_prepared',
        b'{{\\"value\\":7,\\"unexpected\\":true}}',
        b'WsvHost::new_with_subject(MockWorldStateView::default(), caller, HashMap::new())',
        b'caller.clone(),\n            HashMap::new(),',
        b'controller.clone(),\n            HashMap::new(),',
    ),
    'crates/ivm/tests/kotodama_state_name_map_runtime.rs': (
        b'ivm::numeric_tlv::encode_int(',
        b'ivm_abi::numeric_tlv::encode_int(',
        b'use std::{collections::HashMap, str::FromStr};',
        b'WsvHost::new_with_subject(wsv, subject, HashMap::new());',
    ),
}

# The two extracted fixtures changed for the same canonical object-key order as
# their Rust source. Keep their readable contract coupled to the byte seals.
ASSET_REQUIRED_FRAGMENTS = {
    ('crates/ivm/tests/kotodama.rs', '007.ko'):
        b'Json::parse("{\\"cursor\\":1,\\"query\\":\\"sc_dummy\\"}")',
    ('crates/ivm/tests/kotodama.rs', '032.ko'):
        b'Json::parse("{\\"cursor\\":1,\\"query\\":\\"sc_dummy\\"}")',
}
ASSET_FORBIDDEN_FRAGMENTS = {
    ('crates/ivm/tests/kotodama.rs', '007.ko'):
        b'Json::parse("{\\"query\\":\\"sc_dummy\\",\\"cursor\\":1}")',
    ('crates/ivm/tests/kotodama.rs', '032.ko'):
        b'Json::parse("{\\"query\\":\\"sc_dummy\\",\\"cursor\\":1}")',
}

_INCLUDE_RE = re.compile(
    rb'include_str!\([ \t\r\n]*"(?P<path>[^"\r\n]*fixtures/koto_v1/[^"\r\n]+)"[ \t\r\n]*\)'
    rb'(?P<sentinel>[ \t\r\n]*\.strip_suffix\([ \t\r\n]*\'\\n\'[ \t\r\n]*\)'
    rb'[ \t\r\n]*\.expect\([ \t\r\n]*"fixture sentinel newline"[ \t\r\n]*\))?'
)


def _asset_repo_path(source: SourceSpec, asset: AssetSpec) -> Path:
    """Return the repository-relative asset path implied by the source."""

    crate = Path(source.path).parts[1]
    return Path("crates") / crate / "fixtures" / "koto_v1" / Path(source.path).stem / asset.name


def _marker(asset_path: Path) -> bytes:
    """Return the canonical placeholder used by the preimage fingerprint."""

    return f'__KOTODAMA_FIXTURE__("{asset_path.as_posix()}")'.encode()


def _project_asset(spec: AssetSpec, stored: bytes) -> bytes:
    """Apply the checked sentinel projection and validate exact bytes."""

    if spec.sentinel:
        if not stored.endswith(b"\n"):
            raise GuardFailure(f"{spec.name}: missing sentinel newline")
        projected = stored[:-1]
    else:
        projected = stored
    if len(projected) != spec.size:
        raise GuardFailure(f"{spec.name}: projected size drift")
    if hashlib.sha256(projected).hexdigest() != spec.digest:
        raise GuardFailure(f"{spec.name}: projected byte digest drift")
    return projected


def _normalize_source(source: SourceSpec, data: bytes) -> bytes:
    """Replace checked include expressions with canonical preimage markers."""

    for fragment in SOURCE_REQUIRED_FRAGMENTS.get(source.path, ()):
        if fragment not in data:
            raise GuardFailure(f"{source.path}: required reviewed source contract missing")
    for fragment in SOURCE_FORBIDDEN_FRAGMENTS.get(source.path, ()):
        if fragment in data:
            raise GuardFailure(f"{source.path}: stale source contract returned")

    matches = list(_INCLUDE_RE.finditer(data))
    if len(matches) != len(source.assets):
        raise GuardFailure(f"{source.path}: expected {len(source.assets)} fixture includes, found {len(matches)}")
    assets_by_name = {asset.name: asset for asset in source.assets}
    if len(assets_by_name) != len(source.assets):
        raise GuardFailure(f"{source.path}: duplicate fixture asset specification")
    seen_assets: set[str] = set()
    chunks: list[bytes] = []
    cursor = 0
    source_dir = (ROOT / source.path).parent
    for match in matches:
        included = match.group("path").decode()
        name = Path(included).name
        asset = assets_by_name.get(name)
        if asset is None or name in seen_assets:
            raise GuardFailure(f"{source.path}: unknown or repeated fixture include {name}")
        seen_assets.add(name)
        expected_repo_path = _asset_repo_path(source, asset)
        resolved = (source_dir / included).resolve()
        expected = (ROOT / expected_repo_path).resolve()
        if resolved != expected:
            raise GuardFailure(f"{source.path}: include path drift for {asset.name}")
        prefix = data[max(0, match.start() - 96) : match.start()]
        wrapper_projection = re.search(
            rb"CaseSource::Fixture\([ \t\r\n]*$", prefix
        ) is not None
        has_sentinel_projection = (
            match.group("sentinel") is not None or wrapper_projection
        )
        if has_sentinel_projection != asset.sentinel:
            raise GuardFailure(f"{source.path}: sentinel projection drift for {asset.name}")
        chunks.extend((data[cursor:match.start()], _marker(expected_repo_path)))
        cursor = match.end()
    if seen_assets != set(assets_by_name):
        raise GuardFailure(f"{source.path}: fixture include set drift")
    chunks.append(data[cursor:])
    normalized = b"".join(chunks)
    if hashlib.sha256(normalized).hexdigest() != source.skeleton_digest:
        raise GuardFailure(f"{source.path}: non-fixture Rust preimage drift")
    return normalized


def _validate_checkout() -> None:
    """Validate all sources, assets, projections, and the closed asset set."""

    expected_assets: set[Path] = set()
    for source in SOURCES:
        _normalize_source(source, (ROOT / source.path).read_bytes())
        for asset in source.assets:
            repo_path = _asset_repo_path(source, asset)
            expected_assets.add(repo_path)
            stored = (ROOT / repo_path).read_bytes()
            key = (source.path, asset.name)
            required = ASSET_REQUIRED_FRAGMENTS.get(key)
            if required is not None and required not in stored:
                raise GuardFailure(f"{repo_path}: required canonical JSON spelling missing")
            forbidden = ASSET_FORBIDDEN_FRAGMENTS.get(key)
            if forbidden is not None and forbidden in stored:
                raise GuardFailure(f"{repo_path}: stale noncanonical JSON spelling returned")
            _project_asset(asset, stored)
    actual_assets: set[Path] = set()
    for crate in ("ivm", "kotodama_lang", "kotodama_toolchain"):
        fixture_root = ROOT / "crates" / crate / "fixtures" / "koto_v1"
        if fixture_root.exists():
            actual_assets.update(path.relative_to(ROOT) for path in fixture_root.rglob("*.ko"))
    if actual_assets != expected_assets:
        missing = sorted(expected_assets - actual_assets)
        extra = sorted(actual_assets - expected_assets)
        raise GuardFailure(f"fixture asset set drift; missing={missing}, extra={extra}")


class KotodamaFixtureAssetSourceGuard(unittest.TestCase):
    """Keep extraction semantics and mutation failures explicit."""

    def test_checkout_matches_reviewed_current_sources(self) -> None:
        _validate_checkout()

    def test_reviewed_source_contract_mutations_fail_before_digest_checks(self) -> None:
        by_path = {source.path: source for source in SOURCES}
        for path, fragments in SOURCE_REQUIRED_FRAGMENTS.items():
            source = by_path[path]
            data = (ROOT / path).read_bytes()
            for fragment in fragments:
                with self.subTest(path=path, fragment=fragment):
                    self.assertIn(fragment, data)
                    with self.assertRaisesRegex(GuardFailure, "required reviewed source contract"):
                        _normalize_source(source, data.replace(fragment, b"removed source contract"))
        for path, fragments in SOURCE_FORBIDDEN_FRAGMENTS.items():
            source = by_path[path]
            data = (ROOT / path).read_bytes()
            for fragment in fragments:
                with self.subTest(path=path, retired=fragment):
                    self.assertNotIn(fragment, data)
                    with self.assertRaisesRegex(GuardFailure, "stale source contract"):
                        _normalize_source(source, data + b"\n" + fragment)

    def test_include_ownership_and_projection_mutations_fail_closed(self) -> None:
        source = SOURCES[0]
        data = (ROOT / source.path).read_bytes()
        match = next(_INCLUDE_RE.finditer(data))
        include = match.group(0)
        changed = include.replace(match.group("path"), b"../fixtures/koto_v1/foreign/001.ko")
        with self.assertRaisesRegex(GuardFailure, "include path drift"):
            _normalize_source(source, data[:match.start()] + changed + data[match.end():])
        with self.assertRaisesRegex(GuardFailure, "fixture includes"):
            _normalize_source(source, data + b"\n" + include)
        # The current matrix owns sentinel removal through CaseSource::Fixture.
        # Changing that owner must fail before the ordinary skeleton fingerprint.
        self.assertIn(b"CaseSource::Fixture(", data)
        changed = data.replace(b"CaseSource::Fixture(", b"CaseSource::Inline(", 1)
        with self.assertRaisesRegex(GuardFailure, "sentinel projection drift"):
            _normalize_source(source, changed)

    def test_payload_mutation_fails_closed(self) -> None:
        source = SOURCES[0]
        spec = source.assets[0]
        stored = (ROOT / _asset_repo_path(source, spec)).read_bytes()
        mutated = bytes((stored[0] ^ 1,)) + stored[1:]
        with self.assertRaises(GuardFailure):
            _project_asset(spec, mutated)

    def test_sentinel_mutation_fails_closed(self) -> None:
        source, spec = next(
            (source, asset)
            for source in SOURCES
            for asset in source.assets
            if asset.sentinel
        )
        stored = (ROOT / _asset_repo_path(source, spec)).read_bytes()
        with self.assertRaises(GuardFailure):
            _project_asset(replace(spec, sentinel=False), stored)

    def test_rust_skeleton_mutation_fails_closed(self) -> None:
        source = SOURCES[0]
        data = (ROOT / source.path).read_bytes()
        mutated = data.replace(b"#[test]", b"#[cfg(test)]", 1)
        with self.assertRaises(GuardFailure):
            _normalize_source(source, mutated)


if __name__ == "__main__":
    unittest.main()
