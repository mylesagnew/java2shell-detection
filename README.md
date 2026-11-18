# java2shell-detect

Host-side exposure check for **CVE-2026-114938**, for Linux/macOS (Python) and Windows (PowerShell) (Java2Shell / Java4Shell): a heap overflow in
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

Python 3.8+ (CI tests 3.10 to 3.13), standard library only. Run as root on Linux to see every JVM's environment and attach `jcmd`.

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

## Windows (PowerShell)

`java2shell-detect.ps1` is the Windows edition: same checks, verdicts and exit codes, no Python
needed. Runs on Windows PowerShell 5.1 and PowerShell 7+. Run it elevated so it can read every
process.

```powershell
powershell -ExecutionPolicy Bypass -File .\java2shell-detect.ps1
```

```powershell
.\java2shell-detect.ps1 -Json | Out-File "java2shell-$env:COMPUTERNAME.json"
```

| Option | Effect |
|---|---|
| `-Path DIR` | extra search root (repeatable), e.g. an appliance or product install folder |
| `-Deep` | search every fixed drive |
| `-MaxDepth N` | directory depth per root (default 6) |
| `-NoJcmd` | don't attach to running JVMs |
| `-AssumeCpuCapable` | treat the CPU as exposed |
| `-NoInstalls` / `-NoProcesses` | skip one half of the scan |
| `-Json`, `-NoColor` | output format |

What is Windows-specific:

- **Running JVMs are found by the `jvm.dll` they load**, not by process name, so service wrappers
  such as Tomcat/procrun (`tomcat9.exe`, used by Jira and Confluence) are covered too.
- **Service JVM options** are read from the procrun registry key
  (`...\Procrun 2.0\<service>\Parameters\Java\Options`) as well as the command line.
- **Environment options**: Windows doesn't let PowerShell read another process's environment, so
  `JAVA_TOOL_OPTIONS` / `JDK_JAVA_OPTIONS` / `_JAVA_OPTIONS` come from the machine-wide
  environment that services inherit. `jcmd` reports the real flag value when it can attach.
- **Installs** are found under Program Files, ProgramData, `C:\Java`, `C:\Atlassian`, user `.jdks`
  and `.gradle\jdks`, scoop, `JAVA_HOME`, `PATH` and the vendor registry keys (JavaSoft, Adoptium,
  Corretto, Azul, Microsoft, BellSoft, Semeru). With no `release` file the version comes from
  `java.exe`'s version resource, so nothing is executed.
- **Patched but not restarted**: flagged when the loaded `jvm.dll` is gone from disk or `jcmd`
  reports an older version than the install.
- **CPU**: PowerShell 7.1+ reads CPUID leaf 7 directly (exact). Windows PowerShell 5.1 can only ask
  Windows whether AVX-512F exists: without it the CPU is ruled out, with it the CPU is assumed
  capable. Run under `pwsh` for an exact answer.
- `jcmd` often cannot attach to services running as LocalSystem from another account; those JVMs
  fall back to the command line and registry options, and the finding says so.

CI runs the Pester tests and an end-to-end scan on a real Windows runner under both shells, with
two live Temurin 17.0.12 JVMs (one started with `-XX:-UseBASE64Intrinsics`).

## Verdicts and exit codes

| Verdict | Meaning | Exit |
|---|---|---|
| `VULNERABLE` | affected version, capable CPU, intrinsic on | 1 |
| `RESTART_REQUIRED` | fixed build on disk, JVM still running the old one | 1 |
| `MITIGATED` | affected, but the workaround flag is active: still patch | 2 |
| `AFFECTED_VERSION_CPU_NOT_EXPOSED` | affected version on a CPU without VBMI: patch anyway, images move hosts | 2 |
| `REVIEW` | version unreadable or newer than the advisory | 2 |
| `OK` | fixed or never affected | 0 |
| (error) | the scan itself failed (PowerShell edition) | 3 |

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

```powershell
Invoke-Pester -Path tests\java2shell-detect.Tests.ps1 -Output Detailed
```
