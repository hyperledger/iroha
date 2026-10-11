"""Public SOFTWARE DATA profile controls; no compiler, keys or Native runtime."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
spec=importlib.util.spec_from_file_location("private_mobile_hermetic",Path(__file__).parents[1]/"run_mobile_hermetic_command.py")
runner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
class RuntimeTrustTests(unittest.TestCase):
    def environment(self,profile):
        env=dict.fromkeys(runner.PROFILES[profile],"SYNTHETIC public DATA")
        if profile in runner.AUTHENTICATED_CARGO_PROFILES:
            env[runner.WALLET_RUNTIME_TRUST_INPUT]="3"*64
            env[runner.WALLET_RUNTIME_AUTHORITY_INPUT]="bpng-taira-v7"
        return env
    def test_every_authenticated_mobile_profile_requires_the_public_root(self):
        for profile in runner.AUTHENTICATED_CARGO_PROFILES:
            with self.subTest(profile=profile):
                env=self.environment(profile);del env[runner.WALLET_RUNTIME_TRUST_INPUT]
                with self.assertRaises(RuntimeError):runner.validate_profile_environment(profile,env)
    def test_valid_root_is_preserved_by_all_mobile_profiles(self):
        for profile in runner.AUTHENTICATED_CARGO_PROFILES:
            env=self.environment(profile);runner.validate_profile_environment(profile,env)
            self.assertEqual(runner.wallet_runtime_trust(env[runner.WALLET_RUNTIME_TRUST_INPUT]),"3"*64)
    def test_malformed_public_root_refuses_every_mobile_profile(self):
        for profile in runner.AUTHENTICATED_CARGO_PROFILES:
            for value in ["","0"*64,"A"*64,"g"*64,"1"*63,"1"*65,"1"*64+"\n"]:
                with self.subTest(profile=profile,value=value):
                    env=self.environment(profile);env[runner.WALLET_RUNTIME_TRUST_INPUT]=value
                    with self.assertRaises(RuntimeError):runner.validate_profile_environment(profile,env)
    def test_only_exact_explicit_authorities_are_accepted(self):
        for profile in runner.AUTHENTICATED_CARGO_PROFILES:
            for authority in ["bpng-taira-v7", "cbsi-release-v1"]:
                env=self.environment(profile);env[runner.WALLET_RUNTIME_AUTHORITY_INPUT]=authority
                runner.validate_profile_environment(profile,env)
                self.assertEqual(runner.wallet_runtime_authority(authority),authority)
            for authority in ["", "bpng", "cbsi", "bpng-taira-v6", "BPNG-TAIRA-V7", "bpng-taira-v7\n", " cbsi-release-v1"]:
                env=self.environment(profile);env[runner.WALLET_RUNTIME_AUTHORITY_INPUT]=authority
                with self.assertRaises(RuntimeError):runner.validate_profile_environment(profile,env)
    def test_apple_builder_rejects_retired_authority_before_building(self):
        builder = Path(__file__).parents[1] / "build_norito_xcframework.sh"
        result = subprocess.run(
            ["/bin/bash", str(builder)],
            env={
                runner.WALLET_RUNTIME_AUTHORITY_INPUT: "bpng-taira-v6",
                runner.WALLET_RUNTIME_TRUST_INPUT: "3" * 64,
            },
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be bpng-taira-v7 or cbsi-release-v1", result.stderr)
    def test_partial_pair_and_absent_pair_refuse_authenticated_corridors(self):
        for profile in runner.AUTHENTICATED_CARGO_PROFILES:
            for absent in [(runner.WALLET_RUNTIME_AUTHORITY_INPUT,), (runner.WALLET_RUNTIME_TRUST_INPUT,), (runner.WALLET_RUNTIME_AUTHORITY_INPUT,runner.WALLET_RUNTIME_TRUST_INPUT)]:
                env=self.environment(profile)
                for name in absent:del env[name]
                with self.assertRaises(RuntimeError):runner.validate_profile_environment(profile,env)
    def test_non_native_build_profiles_do_not_accept_the_root(self):
        for profile in set(runner.PROFILES)-runner.AUTHENTICATED_CARGO_PROFILES:
            env=self.environment(profile);runner.validate_profile_environment(profile,env)
            env[runner.WALLET_RUNTIME_TRUST_INPUT]="3"*64
            with self.assertRaises(RuntimeError):runner.validate_profile_environment(profile,env)
    def test_other_ambient_flags_remain_closed(self):
        for name in ["RUSTFLAGS","RUSTC_WRAPPER","CARGO_ENCODED_RUSTFLAGS","NATIVE_READY"]:
            env=self.environment("android-cargo");env[name]="offered"
            with self.assertRaises(RuntimeError):runner.validate_profile_environment("android-cargo",env)
    def test_public_root_cannot_replace_any_other_required_input(self):
        for profile in runner.AUTHENTICATED_CARGO_PROFILES:
            for name in runner.PROFILES[profile]:
                env=self.environment(profile);del env[name]
                with self.assertRaises(RuntimeError):runner.validate_profile_environment(profile,env)
if __name__=="__main__":unittest.main()
