#!/usr/bin/env python3
"""java2shell-detect: host-side exposure check for CVE-2026-114938 (Java2Shell / Java4Shell).

The bug is a heap overflow in HotSpot's AVX-512 VBMI Base64 decode intrinsic (C2 JIT).
A host is exposed when ALL of these hold:
  1. the JVM version is in the affected range,
  2. the CPU has avx512f + avx512bw + avx512vbmi + bmi2 (x86-64 only),
  3. the intrinsic is not switched off (-XX:-UseBASE64Intrinsics, -XX:UseAVX<=2, -Xint, ...).

This tool checks those three things locally. It never sends the malformed Base64
trigger to anything: that payload corrupts memory in the target, so a "network probe"
would be an attack, not a scan. Read-only; stdlib only; Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys

__version__ = "1.0.0"
CVE = "CVE-2026-114938"

# First fixed build per line (17 Nov 2026 releases). Vendor build numbers can differ.
FIXED = {17: (17, 0, 21, 1), 21: (21, 0, 13, 1), 25: (25, 0, 5, 1), 27: (27, 0, 1, 1)}
FIRST_AFFECTED_17 = (17, 0, 6)
CPU_FLAGS = ("avx512f", "avx512bw", "avx512vbmi", "bmi2")
OPTION_ENV_VARS = ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS")

# Verdicts, worst first.
VULNERABLE = "VULNERABLE"
RESTART = "RESTART_REQUIRED"
MITIGATED = "MITIGATED"
AFFECTED_CPU_SAFE = "AFFECTED_VERSION_CPU_NOT_EXPOSED"
REVIEW = "REVIEW"
OK = "OK"
ORDER = [VULNERABLE, RESTART, MITIGATED, AFFECTED_CPU_SAFE, REVIEW, OK]

LINUX_ROOTS = ["/usr/lib/jvm", "/usr/lib64/jvm", "/usr/java", "/usr/local", "/opt",
               "/srv", "/usr/share", "/var/lib"]
MAC_ROOTS = ["/Library/Java/JavaVirtualMachines", "~/Library/Java/JavaVirtualMachines",
             "/opt/homebrew/opt", "/opt/homebrew/Cellar", "/usr/local/opt", "/usr/local/Cellar"]
USER_ROOTS = ["~/.sdkman/candidates/java", "~/.gradle/jdks", "~/.jdks", "~/.asdf/installs/java"]
PRUNE = {"/proc", "/sys", "/dev", "/run"}


# ---------------------------------------------------------------- versions

def parse_version(text: str | None):
    """'17.0.21.1', '17.0.21+9-LTS', '1.8.0_412', '21' -> tuple of ints, or None."""
    if not text:
        return None
    s = text.strip().strip('"')
    m = re.match(r"1\.(\d+)\.\d+(?:_(\d+))?", s)
    if m:
        return (int(m.group(1)), 0, int(m.group(2) or 0))
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?", s)
    if not m:
        return None
    return tuple(int(g) for g in m.groups() if g is not None)


def _pad(v, n=4):
    return tuple(v) + (0,) * (n - len(v))


def classify_version(v):
    """Return (status, note). status: affected | fixed | not_affected | unknown."""
    if not v:
        return "unknown", "version could not be read"
    major = v[0]
    if major <= 8:
        return "not_affected", ("Java 8 is not affected, except one Oracle Java 8 Performance "
                                "Pack build: check if this is Oracle Performance Pack")
    if major <= 16:
        return "not_affected", "older than the vulnerable intrinsic"
    if major == 17:
        if _pad(v) < _pad(FIRST_AFFECTED_17):
            return "not_affected", "17 before 17.0.6 has no VBMI decode intrinsic"
    if major in FIXED:
        if _pad(v) >= _pad(FIXED[major]):
            return "fixed", "at or above %s" % ".".join(map(str, FIXED[major]))
        return "affected", "below fixed build %s" % ".".join(map(str, FIXED[major]))
    if major < max(FIXED):
        return "affected", ("Java %d is an end-of-life feature release with no fix: "
                            "move to a patched 17/21/25/27 build" % major)
    return "unknown", "Java %d is newer than the advisory: check vendor notes" % major


# ---------------------------------------------------------------- CPU

def cpu_info():
    arch = platform.machine().lower()
    out = {"arch": arch, "flags": {}, "source": None, "capable": None}
    if arch not in ("x86_64", "amd64", "x64"):
        out["capable"] = False
        out["source"] = "non-x86 architecture"
        return out
    tokens = set()
    if os.path.exists("/proc/cpuinfo"):
        try:
            with open("/proc/cpuinfo") as fh:
                for line in fh:
                    if line.startswith("flags"):
                        tokens = set(line.split(":", 1)[1].split())
                        break
            out["source"] = "/proc/cpuinfo"
        except OSError:
            pass
    elif sys.platform == "darwin":
        txt = _run(["sysctl", "-n", "machdep.cpu.features", "machdep.cpu.leaf7_features"])
        if txt:
            tokens = {t.lower() for t in txt.split()}
            out["source"] = "sysctl"
    if out["source"] is None:
        out["source"] = "unreadable (assuming capable)"
        out["capable"] = True
        return out
    out["flags"] = {f: f in tokens for f in CPU_FLAGS}
    out["capable"] = all(out["flags"].values())
    return out


# ---------------------------------------------------------------- JVM options

def mitigation_from_args(args):
    """Walk JVM options in order (last one wins). Returns (mitigated, reasons)."""
    b64 = None
    useavx = None
    xint = False
    tiered = None
    for a in args:
        if a == "-XX:-UseBASE64Intrinsics":
            b64 = False
        elif a == "-XX:+UseBASE64Intrinsics":
            b64 = True
        elif a == "-Xint":
            xint = True
        else:
            m = re.fullmatch(r"-XX:UseAVX=(\d+)", a)
            if m:
                useavx = int(m.group(1))
            m = re.fullmatch(r"-XX:TieredStopAtLevel=(\d+)", a)
            if m:
                tiered = int(m.group(1))
    reasons = []
    if b64 is False:
        reasons.append("-XX:-UseBASE64Intrinsics")
    if useavx is not None and useavx < 3:
        reasons.append("-XX:UseAVX=%d" % useavx)
    if xint:
        reasons.append("-Xint (no JIT)")
    if tiered is not None and tiered < 4:
        reasons.append("-XX:TieredStopAtLevel=%d (no C2)" % tiered)
    return bool(reasons), reasons


def ordered_jvm_args(cmdline, env):
    """HotSpot reads JAVA_TOOL_OPTIONS, then JDK_JAVA_OPTIONS (launcher), then the
    command line, then _JAVA_OPTIONS, so later entries override earlier ones."""
    def split(name):
        val = env.get(name, "")
        try:
            return shlex.split(val)
        except ValueError:
            return val.split()
    return split("JAVA_TOOL_OPTIONS") + split("JDK_JAVA_OPTIONS") + list(cmdline[1:]) + split("_JAVA_OPTIONS")


def parse_jcmd_flags(text):
    flags = {}
    m = re.search(r"\bUseBASE64Intrinsics\s*[:]?=\s*(true|false)", text)
    if m:
        flags["UseBASE64Intrinsics"] = m.group(1) == "true"
    m = re.search(r"\bUseAVX\s*[:]?=\s*(\d+)", text)
    if m:
        flags["UseAVX"] = int(m.group(1))
    return flags


def parse_jcmd_version(text):
    m = re.search(r"^JDK\s+([0-9][0-9._+\-A-Za-z]*)", text, re.M)
    return m.group(1) if m else None


# ---------------------------------------------------------------- helpers

def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return ""


def read_release(home, root=""):
    """Parse <JAVA_HOME>/release (KEY="value" lines). Returns dict or {}."""
    path = os.path.join(root + home, "release") if root else os.path.join(home, "release")
    data = {}
    try:
        with open(path, errors="replace") as fh:
            for line in fh:
                if "=" in line:
                    k, v = line.split("=", 1)
                    data[k.strip()] = v.strip().strip('"')
    except OSError:
        return {}
    return data


def java_version_exec(java_bin):
    out = _run([java_bin, "-version"], timeout=15)
    m = re.search(r'version "([^"]+)"', out)
    return m.group(1) if m else None


def install_record(home, release, exec_java=False):
    ver = release.get("JAVA_VERSION")
    source = "release file" if ver else None
    if not ver and exec_java:
        ver = java_version_exec(os.path.join(home, "bin", "java"))
        source = "java -version" if ver else None
    return {
        "java_home": home,
        "version": ver,
        "version_source": source,
        "runtime_version": release.get("JAVA_RUNTIME_VERSION"),
        "implementor": release.get("IMPLEMENTOR") or release.get("IMPLEMENTOR_VERSION"),
    }


# ---------------------------------------------------------------- discovery: installs

def candidate_roots(extra, deep):
    if deep:
        return ["/"] + list(extra)
    roots = list(MAC_ROOTS if sys.platform == "darwin" else LINUX_ROOTS) + USER_ROOTS
    homes = [os.environ.get("JAVA_HOME", "")]
    java = shutil.which("java")
    if java:
        homes.append(os.path.dirname(os.path.dirname(os.path.realpath(java))))
    if sys.platform == "darwin":
        homes.append(_run(["/usr/libexec/java_home"]).strip())
    # Only real runtimes (with a release file): skips the macOS /usr/bin/java stub and
    # avoids walking all of /usr.
    roots += [h for h in homes if h.startswith("/") and os.path.isfile(os.path.join(h, "release"))]
    return [os.path.expanduser(r) for r in roots] + list(extra)


def find_installs(roots, max_depth):
    homes = set()
    for root in roots:
        if not os.path.isdir(root):
            continue
        base_depth = root.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if dirpath in PRUNE:
                dirnames[:] = []
                continue
            if dirpath.count("/") - base_depth >= max_depth:
                dirnames[:] = []
            if os.path.basename(dirpath) == "bin" and "java" in filenames:
                jb = os.path.join(dirpath, "java")
                if os.path.isfile(jb) and os.access(jb, os.X_OK):
                    homes.add(os.path.realpath(os.path.dirname(dirpath)))
    # Drop JDK 8 nested jre/ when its parent JDK is also listed.
    return sorted(h for h in homes
                  if not (os.path.basename(h) == "jre" and os.path.dirname(h) in homes))


# ---------------------------------------------------------------- discovery: processes

def _is_java(argv0, exe):
    names = {os.path.basename(argv0 or ""), os.path.basename((exe or "").replace(" (deleted)", ""))}
    return bool(names & {"java", "javaw"})


def linux_processes():
    procs = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit() or int(pid) == os.getpid():
            continue
        base = "/proc/" + pid
        try:
            with open(base + "/cmdline", "rb") as fh:
                argv = [a.decode(errors="replace") for a in fh.read().split(b"\0") if a]
        except OSError:
            continue
        if not argv:
            continue
        try:
            exe = os.readlink(base + "/exe")
        except OSError:
            exe = None
        if not _is_java(argv[0], exe):
            continue
        env = {}
        try:
            with open(base + "/environ", "rb") as fh:
                for kv in fh.read().split(b"\0"):
                    k, _, v = kv.decode(errors="replace").partition("=")
                    if k in OPTION_ENV_VARS:
                        env[k] = v
            env_read = True
        except OSError:
            env_read = False
        libjvm_deleted = None
        try:
            with open(base + "/maps") as fh:
                libjvm = [l for l in fh if "libjvm.so" in l]
            libjvm_deleted = any("(deleted)" in l for l in libjvm) if libjvm else None
        except OSError:
            pass
        try:
            import pwd
            user = pwd.getpwuid(os.stat(base).st_uid).pw_name
        except (KeyError, OSError, ImportError):
            user = None
        exe_path = (exe or argv[0]).replace(" (deleted)", "")
        home = os.path.dirname(os.path.dirname(exe_path)) if exe_path.startswith("/") else None
        procs.append({
            "pid": int(pid), "user": user, "argv": argv, "env": env, "env_read": env_read,
            "java_home": home, "root": base + "/root",
            "binary_deleted": bool(exe and exe.endswith(" (deleted)")),
            "libjvm_deleted": libjvm_deleted,
        })
    return procs


def ps_processes():
    procs = []
    out = _run(["ps", "-axo", "pid=,user=,command="])
    for line in out.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3 or int(parts[0]) == os.getpid():
            continue
        try:
            argv = shlex.split(parts[2])
        except ValueError:
            argv = parts[2].split()
        if not argv or not _is_java(argv[0], None):
            continue
        exe = argv[0]
        if not exe.startswith("/"):
            exe = shutil.which(exe) or exe
        exe = os.path.realpath(exe) if exe.startswith("/") else exe
        home = os.path.dirname(os.path.dirname(exe)) if exe.startswith("/") else None
        procs.append({"pid": int(parts[0]), "user": parts[1], "argv": argv, "env": {},
                      "env_read": False, "java_home": home, "root": "",
                      "binary_deleted": False, "libjvm_deleted": None})
    return procs


def jcmd_probe(proc):
    """Ask the running JVM for its real version and flag values (read-only commands)."""
    jcmd = None
    if proc["java_home"]:
        cand = proc["root"] + os.path.join(proc["java_home"], "bin", "jcmd") if proc["root"] else \
            os.path.join(proc["java_home"], "bin", "jcmd")
        if os.path.isfile(cand) and not proc["root"]:
            jcmd = cand
    jcmd = jcmd or shutil.which("jcmd")
    if not jcmd:
        return None
    prefix = []
    if hasattr(os, "geteuid") and os.geteuid() == 0 and proc["user"] not in (None, "root"):
        if shutil.which("runuser"):
            prefix = ["runuser", "-u", proc["user"], "--"]
        elif shutil.which("sudo"):
            prefix = ["sudo", "-n", "-u", proc["user"]]
    pid = str(proc["pid"])
    ver = _run(prefix + [jcmd, pid, "VM.version"], timeout=15)
    flags = _run(prefix + [jcmd, pid, "VM.flags", "-all"], timeout=15)
    res = {"version": parse_jcmd_version(ver), "flags": parse_jcmd_flags(flags)}
    if not res["version"] and not res["flags"]:
        return None
    return res


# ---------------------------------------------------------------- verdicts

def verdict(vstatus, cpu_capable, mitigated, restart_needed=False):
    if restart_needed:
        return RESTART
    if vstatus == "affected":
        if not cpu_capable:
            return AFFECTED_CPU_SAFE
        return MITIGATED if mitigated else VULNERABLE
    if vstatus == "unknown":
        return REVIEW
    return OK


def assess_install(rec, cpu_capable):
    v = parse_version(rec["version"])
    status, note = classify_version(v)
    rec.update(kind="install", version_status=status, note=note,
               verdict=verdict(status, cpu_capable, mitigated=False))
    if rec["verdict"] == VULNERABLE:
        rec["note"] += "; any JVM started from here without the workaround flag is exposed"
    return rec


def assess_process(proc, cpu_capable, use_jcmd=True):
    rel = read_release(proc["java_home"], proc["root"]) if proc["java_home"] else {}
    rec = install_record(proc["java_home"] or "?", rel, exec_java=False)
    rec.update(kind="process", pid=proc["pid"], user=proc["user"],
               command=" ".join(proc["argv"])[:300])
    probe = jcmd_probe(proc) if use_jcmd else None
    rec["jcmd"] = probe

    args = ordered_jvm_args(proc["argv"], proc["env"])
    mitigated, reasons = mitigation_from_args(args)
    if probe and "UseBASE64Intrinsics" in probe["flags"]:
        # The live flag value beats our reading of the command line.
        live_b64 = probe["flags"]["UseBASE64Intrinsics"]
        live_avx = probe["flags"].get("UseAVX")
        mitigated = (not live_b64) or (live_avx is not None and live_avx < 3) or \
            any("Xint" in r or "TieredStop" in r for r in reasons)
        reasons = ["live: UseBASE64Intrinsics=%s%s" % (
            str(live_b64).lower(), ", UseAVX=%s" % live_avx if live_avx is not None else "")]
    rec["mitigation"] = reasons

    running_ver = (probe or {}).get("version")
    disk_status, disk_note = classify_version(parse_version(rec["version"]))
    run_status = classify_version(parse_version(running_ver))[0] if running_ver else None
    stale = bool(proc["binary_deleted"] or proc["libjvm_deleted"])

    notes = []
    if running_ver:
        rec["running_version"] = running_ver
        status = run_status
        if disk_status == "fixed" and run_status == "affected":
            notes.append("patched on disk, but this JVM still runs %s" % running_ver)
    else:
        status = disk_status
    notes.append(disk_note if not running_ver else classify_version(parse_version(running_ver))[1])
    if stale:
        notes.append("libjvm/java binary was replaced on disk after this JVM started")
    if not proc["env_read"] and sys.platform.startswith("linux"):
        notes.append("could not read process environment (run as root for JAVA_TOOL_OPTIONS)")
    if not probe and use_jcmd:
        notes.append("jcmd attach failed: flags taken from command line only "
                     "(@argfiles / -XX:Flags files not read)")

    restart = (disk_status == "fixed" and (run_status == "affected" or (stale and not running_ver)))
    rec.update(version_status=status, note="; ".join(n for n in notes if n),
               verdict=verdict(status, cpu_capable, mitigated, restart_needed=restart))
    return rec


# ---------------------------------------------------------------- output

COLORS = {VULNERABLE: "31;1", RESTART: "31", MITIGATED: "33", AFFECTED_CPU_SAFE: "33",
          REVIEW: "36", OK: "32"}


def paint(text, verdict_name, enable):
    return "\033[%sm%s\033[0m" % (COLORS[verdict_name], text) if enable else text


def print_report(report, color):
    cpu = report["cpu"]
    print("java2shell-detect %s  %s  host=%s" % (__version__, CVE, report["host"]))
    flags = " ".join("%s=%s" % (k, "yes" if v else "no") for k, v in cpu["flags"].items())
    print("CPU: %s  %s  -> %s (%s)" % (
        cpu["arch"], flags or "-",
        "AVX-512 VBMI path AVAILABLE" if cpu["capable"] else "not exposed",
        cpu["source"]))
    if report.get("cpu_override"):
        print("     (CPU treated as capable because of --assume-cpu-capable)")
    print()
    if not report["findings"]:
        print("No Java runtimes or JVM processes found. Try --deep or --path DIR.")
    for f in sorted(report["findings"], key=lambda r: (ORDER.index(r["verdict"]), r["kind"])):
        label = paint("%-33s" % f["verdict"], f["verdict"], color)
        ver = f.get("running_version") or f["version"] or "?"
        if f["kind"] == "process":
            where = "pid %s (%s) %s" % (f["pid"], f["user"] or "?", f["java_home"])
        else:
            where = f["java_home"]
        print("%s %-10s %-14s %s" % (label, f["kind"], ver, where))
        if f.get("implementor"):
            print("%34s vendor: %s" % ("", f["implementor"]))
        if f.get("mitigation"):
            print("%34s mitigation: %s" % ("", ", ".join(f["mitigation"])))
        if f["note"]:
            print("%34s %s" % ("", f["note"]))
    print()
    counts = ", ".join("%s=%d" % (k, v) for k, v in report["summary"].items() if v)
    print("Summary: " + (counts or "none"))
    if report["summary"].get(VULNERABLE) or report["summary"].get(RESTART):
        print("Fix: upgrade to 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1 (or your vendor's "
              "equivalent) and RESTART the JVM.\nStop-gap: add -XX:-UseBASE64Intrinsics "
              "(e.g. via JAVA_TOOL_OPTIONS) and restart.")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Detect %s (Java2Shell) exposure on this host." % CVE)
    ap.add_argument("--path", action="append", default=[], metavar="DIR",
                    help="extra directory to search for Java runtimes (repeatable; e.g. an "
                         "unpacked container image or appliance)")
    ap.add_argument("--deep", action="store_true", help="search the whole filesystem from /")
    ap.add_argument("--max-depth", type=int, default=8, help="directory depth per root (default 8)")
    ap.add_argument("--no-installs", action="store_true", help="skip the filesystem search")
    ap.add_argument("--no-processes", action="store_true", help="skip running JVMs")
    ap.add_argument("--no-jcmd", action="store_true",
                    help="do not attach jcmd to running JVMs (command line flags only)")
    ap.add_argument("--exec-java", action="store_true",
                    help="run bin/java -version when a runtime has no release file")
    ap.add_argument("--assume-cpu-capable", action="store_true",
                    help="treat the CPU as AVX-512 VBMI capable (for images that will run elsewhere)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)

    cpu = cpu_info()
    capable = True if a.assume_cpu_capable else bool(cpu["capable"])
    findings = []

    if not a.no_processes:
        procs = linux_processes() if os.path.isdir("/proc/self") else ps_processes()
        for p in procs:
            findings.append(assess_process(p, capable, use_jcmd=not a.no_jcmd))

    if not a.no_installs:
        roots = candidate_roots([os.path.abspath(p) for p in a.path], a.deep)
        for home in find_installs(roots, 64 if a.deep else a.max_depth):
            rec = install_record(home, read_release(home), exec_java=a.exec_java)
            findings.append(assess_install(rec, capable))

    summary = {k: sum(1 for f in findings if f["verdict"] == k) for k in ORDER}
    report = {"tool": "java2shell-detect", "tool_version": __version__, "cve": CVE,
              "host": platform.node(), "cpu": cpu, "cpu_override": a.assume_cpu_capable,
              "summary": summary, "findings": findings}
    if a.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print_report(report, color=sys.stdout.isatty() and not a.no_color)

    if summary[VULNERABLE] or summary[RESTART]:
        return 1
    if summary[MITIGATED] or summary[AFFECTED_CPU_SAFE] or summary[REVIEW]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
