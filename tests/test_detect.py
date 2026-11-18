import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import java2shell_detect as d  # noqa: E402


class VersionTests(unittest.TestCase):
    def status(self, s):
        return d.classify_version(d.parse_version(s))[0]

    def test_parse(self):
        self.assertEqual(d.parse_version("1.8.0_412"), (8, 0, 412))
        self.assertEqual(d.parse_version('"17.0.21+9-LTS"'), (17, 0, 21))
        self.assertEqual(d.parse_version("21.0.13.1"), (21, 0, 13, 1))
        self.assertEqual(d.parse_version("25"), (25,))
        self.assertIsNone(d.parse_version("garbage"))

    def test_17_line(self):
        self.assertEqual(self.status("17.0.5"), "not_affected")
        self.assertEqual(self.status("17.0.6"), "affected")
        self.assertEqual(self.status("17.0.21"), "affected")
        self.assertEqual(self.status("17.0.21.1"), "fixed")
        self.assertEqual(self.status("17.0.22"), "fixed")

    def test_other_lines(self):
        self.assertEqual(self.status("21.0.13"), "affected")
        self.assertEqual(self.status("21.0.13.1"), "fixed")
        self.assertEqual(self.status("25.0.5"), "affected")
        self.assertEqual(self.status("25.0.5.1"), "fixed")
        self.assertEqual(self.status("27.0.1"), "affected")
        self.assertEqual(self.status("27.0.1.1"), "fixed")
        self.assertEqual(self.status("27"), "affected")

    def test_unaffected_and_eol(self):
        self.assertEqual(self.status("1.8.0_412"), "not_affected")
        self.assertEqual(self.status("11.0.25"), "not_affected")
        self.assertEqual(self.status("23.0.2"), "affected")   # EOL, no fix
        self.assertEqual(self.status("28.0.0"), "unknown")
        self.assertEqual(self.status(None), "unknown")


class FlagTests(unittest.TestCase):
    def test_workaround(self):
        self.assertTrue(d.mitigation_from_args(["-XX:-UseBASE64Intrinsics"])[0])
        self.assertTrue(d.mitigation_from_args(["-XX:UseAVX=2"])[0])
        self.assertTrue(d.mitigation_from_args(["-Xint"])[0])
        self.assertTrue(d.mitigation_from_args(["-XX:TieredStopAtLevel=1"])[0])
        self.assertFalse(d.mitigation_from_args(["-Xmx2g", "-XX:UseAVX=3"])[0])

    def test_last_flag_wins(self):
        self.assertFalse(d.mitigation_from_args(
            ["-XX:-UseBASE64Intrinsics", "-XX:+UseBASE64Intrinsics"])[0])

    def test_env_order(self):
        env = {"JAVA_TOOL_OPTIONS": "-XX:-UseBASE64Intrinsics",
               "_JAVA_OPTIONS": "-XX:+UseBASE64Intrinsics"}
        args = d.ordered_jvm_args(["java", "-jar", "app.jar"], env)
        self.assertFalse(d.mitigation_from_args(args)[0])
        env = {"JAVA_TOOL_OPTIONS": "-XX:-UseBASE64Intrinsics"}
        self.assertTrue(d.mitigation_from_args(d.ordered_jvm_args(["java"], env))[0])

    def test_jcmd_parsing(self):
        flags = ("     bool UseBASE64Intrinsics                      = false     "
                 "{ARCH product} {command line}\n     intx UseAVX   = 3   {ARCH product} {default}\n")
        self.assertEqual(d.parse_jcmd_flags(flags), {"UseBASE64Intrinsics": False, "UseAVX": 3})
        ver = "12345:\nOpenJDK 64-Bit Server VM version 21.0.13+11-LTS\nJDK 21.0.13\n"
        self.assertEqual(d.parse_jcmd_version(ver), "21.0.13")


class VerdictTests(unittest.TestCase):
    def test_matrix(self):
        self.assertEqual(d.verdict("affected", True, False), d.VULNERABLE)
        self.assertEqual(d.verdict("affected", True, True), d.MITIGATED)
        self.assertEqual(d.verdict("affected", False, False), d.AFFECTED_CPU_SAFE)
        self.assertEqual(d.verdict("fixed", True, False), d.OK)
        self.assertEqual(d.verdict("fixed", True, False, restart_needed=True), d.RESTART)
        self.assertEqual(d.verdict("unknown", True, False), d.REVIEW)

    def proc(self, home, argv, **kw):
        p = {"pid": 1, "user": "app", "argv": argv, "env": {}, "env_read": True,
             "java_home": home, "root": "", "binary_deleted": False, "libjvm_deleted": False}
        p.update(kw)
        return p

    def fake_home(self, version):
        home = tempfile.mkdtemp()
        with open(os.path.join(home, "release"), "w") as fh:
            fh.write('JAVA_VERSION="%s"\nIMPLEMENTOR="Eclipse Adoptium"\n' % version)
        return home

    def test_process_patched_but_not_restarted(self):
        home = self.fake_home("21.0.13.1")
        rec = d.assess_process(self.proc(home, ["java", "-jar", "x.jar"], libjvm_deleted=True),
                               cpu_capable=True, use_jcmd=False)
        self.assertEqual(rec["verdict"], d.RESTART)

    def test_process_vulnerable_and_mitigated(self):
        home = self.fake_home("17.0.12")
        rec = d.assess_process(self.proc(home, ["java", "-jar", "x.jar"]), True, use_jcmd=False)
        self.assertEqual(rec["verdict"], d.VULNERABLE)
        rec = d.assess_process(self.proc(home, ["java", "-XX:-UseBASE64Intrinsics", "-jar", "x.jar"]),
                               True, use_jcmd=False)
        self.assertEqual(rec["verdict"], d.MITIGATED)

    def test_install_discovery(self):
        root = tempfile.mkdtemp()
        home = os.path.join(root, "opt", "jdk-17.0.9")
        os.makedirs(os.path.join(home, "bin"))
        java = os.path.join(home, "bin", "java")
        open(java, "w").close()
        os.chmod(java, 0o755)
        with open(os.path.join(home, "release"), "w") as fh:
            fh.write('JAVA_VERSION="17.0.9"\n')
        homes = d.find_installs([root], 8)
        self.assertEqual(homes, [os.path.realpath(home)])
        rec = d.assess_install(d.install_record(homes[0], d.read_release(homes[0])), True)
        self.assertEqual(rec["verdict"], d.VULNERABLE)


if __name__ == "__main__":
    unittest.main()
