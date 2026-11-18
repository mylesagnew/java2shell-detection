# java2shell-detect

Host-side exposure check for **CVE-2026-114938** (Java2Shell / Java4Shell): a heap overflow in
HotSpot's AVX-512 VBMI `java.util.Base64` decode intrinsic.

A JVM is exposed only when all three hold, and this tool checks each one:

| Check | How |
|---|---|
| Affected version | `release` file of every runtime found, live `jcmd VM.version` for running JVMs |
| Capable CPU | x86-64 with `avx512f avx512bw avx512vbmi bmi2` (`/proc/cpuinfo`, or `sysctl` on macOS) |
| Intrinsic still on | `-XX:-UseBASE64Intrinsics`, `-XX:UseAVX<=2`, `-Xint`, `-XX:TieredStopAtLevel<4` in the command line and `JAVA_TOOL_OPTIONS` / `JDK_JAVA_OPTIONS` / `_JAVA_OPTIONS`; live `jcmd VM.flags` wins when available |

It also flags JVMs that were **patched on disk but not restarted** (`libjvm.so (deleted)` in
`/proc/<pid>/maps`, or `jcmd` reporting an older version than the disk).

**It does not send the malformed Base64 trigger to anything.** That input corrupts memory in the
target, so a network probe is an attack, not a scan. And because the app usually answers a clean
401/400 and the JIT may deoptimise after one hit, a probe could not prove a host safe anyway.

## Usage

Python 3.8+, standard library only. Run as root on Linux to see every JVM's environment and attach `jcmd`.

```bash
sudo ./java2shell_detect.py
```

```bash
sudo ./java2shell_detect.py --json > java2shell-$(hostname).json
```

Scan an unpacked container image or appliance for bundled JREs (it will run elsewhere, so assume the CPU is capable):

```bash
mkdir img && docker export <container> | tar -x -C img && ./java2shell_detect.py --path img --assume-cpu-capable --no-processes
```

| Option | Effect |
|---|---|
| `--path DIR` | extra search root (repeatable) |
| `--deep` | search all of `/` |
| `--no-jcmd` | don't attach to running JVMs (command-line flags only) |
| `--exec-java` | run `bin/java -version` when a runtime has no `release` file |
| `--assume-cpu-capable` | treat the CPU as exposed |
| `--no-installs` / `--no-processes` | skip one half of the scan |

JVMs running inside containers are found from the host through `/proc/<pid>/root`.

## Verdicts and exit codes

| Verdict | Meaning | Exit |
|---|---|---|
| `VULNERABLE` | affected version, capable CPU, intrinsic on | 1 |
| `RESTART_REQUIRED` | fixed build on disk, JVM still running the old one | 1 |
| `MITIGATED` | affected, but the workaround flag is active: still patch | 2 |
| `AFFECTED_VERSION_CPU_NOT_EXPOSED` | affected version on a CPU without VBMI: patch anyway, images move hosts | 2 |
| `REVIEW` | version unreadable or newer than the advisory | 2 |
| `OK` | fixed or never affected | 0 |

## Affected ranges used

| Line | Affected | First fixed |
|---|---|---|
| 8, 11 | no (one Oracle Java 8 Performance Pack build is listed: check by hand) | — |
| 17 | 17.0.6 – 17.0.21 | 17.0.21.1 |
| 21 | before 21.0.13.1 | 21.0.13.1 |
| 25 | before 25.0.5.1 | 25.0.5.1 |
| 27 | before 27.0.1.1 | 27.0.1.1 |
| 18–20, 22–24, 26 | treated as affected, no fix (end-of-life) | upgrade to a patched line |

Vendors (Temurin, Corretto, Zulu, Red Hat, Microsoft...) may number their fixed builds differently.
If your vendor ships the fix as, say, `17.0.21+N`, this tool reports it as affected: check the
vendor notes and confirm with `jcmd <pid> VM.flags -all | grep UseBASE64Intrinsics`.

## Limits

- `@argfiles`, `-XX:Flags=` and `-XX:VMOptionsFile=` are not read; `jcmd` covers them when it can attach.
- Runtimes without a `release` file show as `REVIEW` unless you pass `--exec-java`.
- Process scanning is from `/proc` on Linux and `ps` elsewhere (no environment or `maps` there).

## Fix

Upgrade to the 17 Nov 2026 builds and restart the JVM. Until then, add `-XX:-UseBASE64Intrinsics`
(or `-XX:UseAVX=2`) and restart.

## Tests

```bash
python3 -m unittest -v tests/test_detect.py
```
