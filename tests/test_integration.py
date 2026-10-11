"""Regression tests using isolated PAM configs and mocked TPM/face operations."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import pwd
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pam_plan", ROOT / "tools/flatten-pam.py")
plan = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plan
spec.loader.exec_module(plan)


def executable(path, contents):
    path.write_text(contents)
    path.chmod(0o700)


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_tmp = tempfile.TemporaryDirectory(prefix="howdy-tpm-tests-")
        cls.build = Path(cls.build_tmp.name)
        cc = shlex.split(os.environ.get("CC", "cc"))
        flags = shlex.split(os.environ.get("CPPFLAGS", "")) + ["-D_GNU_SOURCE", "-Wall", "-Wextra"]
        libs = shlex.split(os.environ.get("LIBS", "-lpam"))
        cls.module = cls.build / "pam_howdy_tpm.so"
        subprocess.run(cc + flags + ["-fPIC", "-shared", "-o", str(cls.module),
                       str(ROOT / "src/pam_howdy_tpm.c"), str(ROOT / "tests/unseal_fixture.c"),
                       "-Wl,--wrap=stat", "-Wl,--wrap=execl"] + libs, check=True)
        cls.fixture = cls.build / "fixture.so"
        subprocess.run(cc + flags + ["-fPIC", "-shared", "-o", str(cls.fixture),
                       str(ROOT / "tests/pam_fixture.c")] + libs, check=True)
        cls.pamtest = cls.build / "pamtest"
        subprocess.run(cc + flags + ["-o", str(cls.pamtest), str(ROOT / "tests/pamtest.c")] + libs, check=True)
        if "PAM_TEST_MODULE_DIR" in os.environ:
            cls.system_modules = Path(os.environ["PAM_TEST_MODULE_DIR"])
        else:
            libdir = subprocess.check_output(["pkg-config", "--variable=libdir", "pam"], text=True).strip()
            if not libdir:
                raise RuntimeError("PAM development metadata missing")
            cls.system_modules = Path(libdir) / "security"

    @classmethod
    def tearDownClass(cls):
        cls.build_tmp.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="howdy-tpm-case-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.config = self.base / "pam.d"
        self.config.mkdir()
        self.modules = self.base / "modules"
        self.modules.mkdir()
        for name, source in {
            "pam_howdy.so": self.fixture, "pam_kwallet5.so": self.fixture,
            "pam_selinux_permit.so": self.fixture,
            "pam_howdy_tpm.so": self.module,
            "pam_permit.so": self.system_modules / "pam_permit.so",
            "pam_deny.so": self.system_modules / "pam_deny.so",
        }.items():
            (self.modules / name).symlink_to(source)
        self.cred = self.base / "secret.cred"
        self.cred.write_text("encrypted-fixture")
        self.cred.chmod(0o600)
        self.mock = self.base / "decrypt"
        executable(self.mock, '#!/bin/bash\nprintf called >> "$UNSEAL_LOG"\nprintf audit-only-secret\n')
        self.env = {**os.environ, "FIXTURE_CRED": str(self.cred), "MOCK_DECRYPT": str(self.mock),
                    "UNSEAL_LOG": str(self.base / "unseal.log"), "OBSERVER_LOG": str(self.base / "observer.log")}
        (self.config / "password-auth").write_text(f"auth required {self.fixture} password\n")
        (self.config / "login").write_text(
            f"auth sufficient {self.modules}/pam_howdy.so face\n"
            "auth substack password-auth\n"
            f"-auth optional {self.modules}/pam_kwallet5.so observe\n"
            f"-session optional {self.modules}/pam_kwallet5.so auto_start\n")

    def apply_plan(self):
        with contextlib.redirect_stdout(io.StringIO()):
            name, fragment, parent = plan.configuration_plan(
                self.config, "login", "alice", "kwallet", self.modules, str(self.cred), "howdy-tpm")
        (self.config / name).write_text("".join(fragment))
        (self.config / "login").write_text("".join(parent))

    def authenticate(self, service="login", user="alice", **env):
        return subprocess.run([str(self.pamtest), service, user, str(self.config)],
                              env={**self.env, **env}, text=True, capture_output=True, timeout=10)

    def test_generated_face_success_releases_before_early_return(self):
        self.apply_plan()
        result = self.authenticate(FACE_OK="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.base / "unseal.log").exists())
        self.assertEqual((self.base / "observer.log").read_text(), "present=1 fixture=1 typed=0\n")

    def test_generated_password_path_keeps_typed_token(self):
        self.apply_plan()
        result = self.authenticate(FACE_OK="0", PASSWORD_OK="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.base / "unseal.log").exists())
        self.assertEqual((self.base / "observer.log").read_text(), "present=1 fixture=0 typed=1\n")

    def test_generated_failed_auth_never_unseals(self):
        self.apply_plan()
        self.assertEqual(self.authenticate(FACE_OK="0", PASSWORD_OK="0").returncode, 1)
        self.assertFalse((self.base / "unseal.log").exists())
        self.assertEqual((self.base / "observer.log").read_text(), "present=0 fixture=0 typed=0\n")

    def test_failed_selinux_guard_never_unseals_even_with_face_success(self):
        login = self.config / "login"
        login.write_text(
            f"auth [success=done ignore=ignore default=bad] {self.modules}/pam_selinux_permit.so guard\n"
            + login.read_text())
        self.apply_plan()
        self.assertEqual(self.authenticate(FACE_OK="1").returncode, 1)
        self.assertFalse((self.base / "unseal.log").exists())
        self.assertFalse((self.base / "observer.log").exists())
        self.assertEqual(self.authenticate(FACE_OK="1", GUARD_OK="1").returncode, 0)
        self.assertTrue((self.base / "unseal.log").exists())

    def test_other_user_never_receives_the_credential(self):
        self.apply_plan()
        self.assertEqual(self.authenticate(user="bob", FACE_OK="1").returncode, 0)
        self.assertFalse((self.base / "unseal.log").exists())
        self.assertIn("present=0", (self.base / "observer.log").read_text())

    def test_other_service_never_receives_the_credential(self):
        self.apply_plan()
        (self.config / "other-login").write_text((self.config / "login").read_text())
        self.assertEqual(self.authenticate(service="other-login", FACE_OK="1").returncode, 0)
        self.assertFalse((self.base / "unseal.log").exists())

    def test_missing_scope_fails_closed_and_existing_token_is_preserved(self):
        self.apply_plan()
        fragment = self.config / "howdy-tpm-face-login"
        fragment.write_text(fragment.read_text().replace("user=alice service=login ", ""))
        self.assertEqual(self.authenticate(FACE_OK="1").returncode, 0)
        self.assertFalse((self.base / "unseal.log").exists())
        (self.config / "existing").write_text(
            f"auth required {self.fixture} password\n"
            f"auth optional {self.module} user=alice service=existing cred={self.cred}\n"
            f"auth optional {self.fixture} observe\n")
        self.assertEqual(self.authenticate(service="existing", PASSWORD_OK="1").returncode, 0)
        self.assertFalse((self.base / "unseal.log").exists())
        self.assertIn("typed=1", (self.base / "observer.log").read_text())

    def test_unsafe_credential_is_not_read(self):
        self.apply_plan()
        self.cred.chmod(0o644)
        self.assertEqual(self.authenticate(FACE_OK="1").returncode, 0)
        self.assertFalse((self.base / "unseal.log").exists())
        self.cred.chmod(0o600)
        self.assertEqual(self.authenticate(FACE_OK="1", BAD_OWNER="1").returncode, 0)
        self.assertFalse((self.base / "unseal.log").exists())
        self.cred.unlink()
        self.assertEqual(self.authenticate(FACE_OK="1").returncode, 0)
        self.assertFalse((self.base / "unseal.log").exists())

    def test_repeated_includes_and_substack_are_displayed(self):
        (self.config / "tree").write_text("auth include password-auth\nauth include password-auth\nauth substack password-auth\n")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            plan.show_stack(self.config, "tree")
        self.assertEqual(output.getvalue().count("password-auth\n"), 6)
        self.assertIn("substack password-auth", output.getvalue())

    def test_unsupported_and_authselect_managed_plans_are_refused(self):
        for control in ("[success=1 default=ignore]", "required"):
            text = (self.config / "login").read_text()
            (self.config / "login").write_text(text.replace("sufficient", control))
            with self.assertRaises(ValueError):
                self.apply_plan()
            (self.config / "login").write_text(text)
        text = (self.config / "login").read_text()
        (self.config / "login").write_text(f"auth required {self.modules}/pam_deny.so\n" + text)
        with self.assertRaisesRegex(ValueError, "before Howdy"):
            self.apply_plan()
        (self.config / "login").write_text(text)
        managed = self.base / "authselect"
        managed.mkdir()
        (managed / "login").write_text((self.config / "login").read_text())
        (self.config / "login").unlink()
        (self.config / "login").symlink_to(managed / "login")
        with self.assertRaisesRegex(ValueError, "authselect"):
            self.apply_plan()

    def shell_environment(self):
        bindir = self.base / "bin"
        bindir.mkdir()
        executable(bindir / "systemd-analyze", "#!/bin/bash\nexit 0\n")
        executable(bindir / "chown", "#!/bin/bash\nexit 0\n")
        executable(bindir / "systemd-creds", '''#!/bin/bash
if [[ $1 == encrypt ]]; then
  cat > "${!#}"
  [[ ${ENCRYPT_FAIL:-0} == 0 ]]
else
  [[ ${VERIFY_FAIL:-0} == 0 ]]
fi
''')
        return {**os.environ, "PATH": str(bindir) + ":" + os.environ["PATH"]}

    def test_enrollment_preserves_spaces_and_failed_replacement(self):
        env = self.shell_environment()
        script = self.base / "enroll"
        # Only the unprivileged scratch copy bypasses EUID; tools are mocked.
        script.write_text((ROOT / "scripts/howdy-tpm-enroll").read_text().replace("[[ $EUID -eq 0 ]] ||", "true ||"))
        output = self.base / "enrolled.cred"
        command = ["bash", str(script), "--cred", str(output)]
        result = subprocess.run(command, input="  fixture  \n  fixture  \n", env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(output.read_text(), "  fixture  ")
        for failure in ("VERIFY_FAIL", "ENCRYPT_FAIL"):
            result = subprocess.run(command, input="y\nreplacement\nreplacement\n", env={**env, failure: "1"}, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_text(), "  fixture  ")
            self.assertFalse(list(self.base.glob(".howdy-tpm.*")))

    def test_cli_propagates_auth_failure_and_distinguishes_wallet_state(self):
        env = self.shell_environment()
        executable(self.base / "bin/runuser", '#!/bin/bash\nprintf "%s\\n" "${WALLET_RESULT:-b true}"\nexit "${WALLET_STATUS:-0}"\n')
        helpers = self.base / "helpers"
        helpers.mkdir()
        executable(helpers / "pamtest", '#!/bin/bash\nexit "${AUTH_STATUS:-1}"\n')
        script = self.base / "cli"
        script.write_text((ROOT / "scripts/howdy-tpm").read_text().replace("[[ $EUID -eq 0 ]] ||", "true ||"))
        env["HOWDY_TPM_LIBEXECDIR"] = str(helpers)
        command = ["bash", str(script), "test", "--service", "login", "--user", pwd.getpwuid(os.getuid()).pw_name]
        result = subprocess.run(command, env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        result = subprocess.run(command, env={**env, "AUTH_STATUS": "0"}, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Wallet unlock: not checked", result.stdout)
        for wallet, expected in (("b true", 0), ("b false", 1)):
            result = subprocess.run(command + ["--wallet", "kdewallet"], env={**env, "AUTH_STATUS": "0", "WALLET_RESULT": wallet}, text=True, capture_output=True)
            self.assertEqual(result.returncode, expected)

    def test_doctor_is_read_only_and_never_requests_decryption(self):
        env = self.shell_environment()
        executable(self.base / "bin/systemd-creds",
                   '#!/bin/bash\nprintf called >> "$UNSEAL_LOG"\nexit 99\n')
        env.update(self.env)
        env["PATH"] = str(self.base / "bin") + ":" + os.environ["PATH"]
        env["HOWDY_TPM_LIBEXECDIR"] = str(ROOT / "tools")
        before = {p.name: p.read_bytes() for p in self.config.iterdir()}
        credential = self.cred.read_bytes()
        command = [
            "bash", str(ROOT / "scripts/howdy-tpm"), "doctor", "--service", "login",
            "--user", pwd.getpwuid(os.getuid()).pw_name, "--keyring", "kwallet",
            "--pam-dir", str(self.config), "--module-dir", str(self.modules),
            "--cred", str(self.cred)]
        result = subprocess.run(command, env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Review-only plan", result.stdout)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.config.iterdir()})
        self.assertEqual(credential, self.cred.read_bytes())
        self.assertFalse((self.base / "unseal.log").exists())
        result = subprocess.run(command + ["--emit-shell"], env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith("# Review before running"))
        self.assertNotIn("Authentication files", result.stdout)
        self.assertIn("Authentication files", result.stderr)
        self.assertEqual(subprocess.run(["bash", "-n"], input=result.stdout, text=True).returncode, 0)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.config.iterdir()})
        self.assertFalse((self.base / "unseal.log").exists())

    def emitted_shell(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            _, fragment, changed = plan.configuration_plan(
                self.config, "login", "alice", "kwallet", self.modules,
                str(self.cred), "howdy-tpm", emit_shell=True)
        # All execution paths, sudo and TPM operations remain isolated/mocked.
        script = output.getvalue().replace("/var/backups/howdy-tpm", str(self.base / "backups"))
        return script, "".join(fragment), "".join(changed)

    def shell_setup_environment(self):
        env = {**self.env, **self.shell_environment()}
        executable(self.base / "bin/sudo", '#!/bin/bash\nexec "$@"\n')
        executable(self.base / "bin/restorecon", '#!/bin/bash\nexit 0\n')
        executable(self.base / "bin/systemd-creds", '''#!/bin/bash
printf called >> "$UNSEAL_LOG"
[[ ${VERIFY_FAIL:-0} == 0 ]] || exit 1
[[ ${EMPTY_CRED:-0} == 1 ]] || printf audit-only-secret
exit 0
''')
        return env

    def test_emitted_shell_preserves_content_permissions_and_can_rollback(self):
        renamed = self.base / "pam's configs"
        self.config.rename(renamed)
        self.config = renamed
        pam = self.config / "login"
        marker = self.base / "must-not-execute"
        pam.write_text(pam.read_text() + f"# $(touch {marker}) 'literal quote'\n\n\n")
        pam.chmod(0o640)
        original = pam.read_bytes()
        script, fragment, changed = self.emitted_shell()
        env = self.shell_setup_environment()
        result = subprocess.run(["bash"], input=script, env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(pam.read_bytes(), changed.encode())
        self.assertEqual(pam.stat().st_mode & 0o777, 0o640)
        self.assertEqual((self.config / "howdy-tpm-face-login").read_text(), fragment)
        self.assertFalse(marker.exists())
        backups = list((self.base / "backups").iterdir())
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), original)
        repeated = subprocess.run(["bash"], input=script, env=env, text=True, capture_output=True)
        self.assertNotEqual(repeated.returncode, 0)
        self.assertEqual(backups[0].read_bytes(), original)
        rollback = next(line.removeprefix("Rollback: ") for line in result.stdout.splitlines()
                        if line.startswith("Rollback: "))
        # A failed restoration must leave the active fragment in place.
        executable(self.base / "bin/cp", '#!/bin/bash\nexit 1\n')
        failed = subprocess.run(["bash", "-c", rollback], env=env, text=True, capture_output=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(pam.read_bytes(), changed.encode())
        self.assertEqual((self.config / "howdy-tpm-face-login").read_text(), fragment)
        (self.base / "bin/cp").unlink()
        restored = subprocess.run(["bash", "-c", rollback], env=env, text=True, capture_output=True)
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertEqual(pam.read_bytes(), original)
        self.assertFalse((self.config / "howdy-tpm-face-login").exists())
        new_script, new_fragment, new_changed = self.emitted_shell()
        reapplied = subprocess.run(["bash"], input=new_script, env=env, text=True, capture_output=True)
        self.assertEqual(reapplied.returncode, 0, reapplied.stdout + reapplied.stderr)
        self.assertEqual(pam.read_bytes(), new_changed.encode())
        self.assertEqual((self.config / "howdy-tpm-face-login").read_text(), new_fragment)

    def test_emitted_shell_refuses_stale_config_or_existing_fragment_before_decrypting(self):
        script, _, _ = self.emitted_shell()
        env = self.shell_setup_environment()
        pam = self.config / "login"
        original = pam.read_bytes()
        pam.write_bytes(original + b"# changed after planning\n")
        result = subprocess.run(["bash"], input=script, env=env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("configuration changed", result.stderr)
        self.assertFalse((self.base / "unseal.log").exists())
        self.assertFalse((self.base / "backups").exists())
        pam.write_bytes(original)
        fragment = self.config / "howdy-tpm-face-login"
        fragment.symlink_to(self.base / "absent")
        result = subprocess.run(["bash"], input=script, env=env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Fragment already exists", result.stderr)
        self.assertTrue(fragment.is_symlink())
        self.assertFalse((self.base / "unseal.log").exists())

    def test_emitted_shell_does_not_write_when_credential_verification_fails(self):
        script, _, _ = self.emitted_shell()
        env = self.shell_setup_environment()
        original = (self.config / "login").read_bytes()
        for failure in ("VERIFY_FAIL", "EMPTY_CRED"):
            result = subprocess.run(["bash"], input=script, env={**env, failure: "1"},
                                    text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((self.config / "login").read_bytes(), original)
            self.assertFalse((self.config / "howdy-tpm-face-login").exists())
            self.assertFalse((self.base / "backups").exists())

    def test_staged_install_uses_pam_metadata_and_installs_all_helpers(self):
        env = self.shell_environment()
        executable(self.base / "bin/pkg-config", '#!/bin/bash\nprintf /opt/test-pam/lib64\n')
        source = self.base / "source"
        source.mkdir()
        for folder in ("src", "tests", "scripts", "tools"):
            (source / folder).mkdir()
        for file in ("Makefile", "src/pam_howdy_tpm.c", "tests/pamtest.c",
                     "scripts/howdy-tpm", "scripts/howdy-tpm-enroll", "tools/flatten-pam.py"):
            shutil.copy2(ROOT / file, source / file)
        stage = self.base / "stage"
        command = ["make", "-C", str(source), f"DESTDIR={stage}", "PREFIX=/usr"]
        result = subprocess.run(command + ["install"], env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = ("opt/test-pam/lib64/security/pam_howdy_tpm.so",
                    "usr/bin/howdy-tpm", "usr/bin/howdy-tpm-enroll",
                    "usr/libexec/howdy-tpm/flatten-pam.py", "usr/libexec/howdy-tpm/pamtest")
        for file in expected:
            self.assertTrue((stage / file).is_file(), file)
        self.assertEqual((stage / "etc/howdy-tpm").stat().st_mode & 0o777, 0o700)
        self.assertFalse((stage / "usr/lib/security/pam_howdy_tpm.so").exists())
        env.pop("HOWDY_TPM_LIBEXECDIR", None)
        result = subprocess.run([
            str(stage / "usr/bin/howdy-tpm"), "doctor", "--service", "login",
            "--user", pwd.getpwuid(os.getuid()).pw_name, "--keyring", "kwallet",
            "--pam-dir", str(self.config), "--module-dir", str(self.modules),
            "--cred", str(self.cred)], env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Review-only plan", result.stdout)
        result = subprocess.run(command + ["uninstall"], env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for file in expected:
            self.assertFalse((stage / file).exists(), file)
        executable(self.base / "bin/pkg-config", '#!/bin/bash\nexit 1\n')
        result = subprocess.run(command + ["install"], env=env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("set SECDIR explicitly", result.stderr)
        self.assertFalse((stage / expected[0]).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
