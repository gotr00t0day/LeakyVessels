# LeakyVessels

Small Linux helper that checks whether the host’s **`runc`** version is in the range affected by **CVE-2024-21626** (“Leaky Vessels”). That class of issues can, under the right conditions, weaken container isolation with respect to the host filesystem—so knowing if you are still on a vulnerable runtime matters for patching and image rebuilds.

Author: c0d3Ninja (see source header).

## What it does

- Looks for `runc` in common paths (`/usr/bin/runc`, `/usr/local/sbin/runc`, `/usr/sbin/runc`) or on `PATH` via `which`.
- If found, runs `runc --version` and parses the reported version string.
- Compares the version to the tool’s internal threshold: runc **before 1.1.12** is treated as **vulnerable**; **1.1.12 and newer** as not vulnerable (for normal `X.Y.Z` style versions).

There is **no CLI**: run the binary and read stdout.

## Output

- Prints an ASCII banner and `Checking for CVE-2024-21626..`.
- If `runc` is found: prints `Found: runc <version>`.
- If the version parses as vulnerable: prints that version in **red** with `Vulnerable to Leaky Vessels`.
- If `runc` is not found: **yellow** message `runc not found!`

## Requirements

- A system where `runc` may be installed (typical: Linux nodes running containers with runc as the low-level runtime).
- C++17 or newer (`std::filesystem`); the project uses **C++20** in other targets—using C++20 here matches the rest of the repo.
- POSIX-style `popen` / `system` (Linux, etc.).

## Build (standalone)

From the repository root:

```bash
g++ -std=c++20 -Wall -Wextra -O2 -o leakyvessels tools/leakyvessels.cpp
```

Or from `tools/`:

```bash
g++ -std=c++20 -Wall -Wextra -O2 -o leakyvessels leakyvessels.cpp
```

No libraries beyond the C++ standard library and the system C/POSIX layer are required.

## ShadowHarvester

`leakyvessels.cpp` is **not** linked into the main `shadowharvester` binary in the project `Makefile`; it is intended as a **standalone** utility alongside other `tools/` programs.

## Files

| File | Role |
|------|------|
| `tools/leakyvessels.cpp` | Implementation and `main()` |

## Limitations

- **Version parsing** expects dot-separated numeric components (e.g. `1.1.11`). Unusual vendor suffixes or non-numeric segments can break `parse_version` or give misleading results.
- **Presence of `runc` on disk** does not mean every workload uses it (e.g. other runtimes may be default). This tool only reflects the `runc` binary it finds.
- **Remediation** is operational: upgrade `runc` to a fixed release (e.g. **≥ 1.1.12** per upstream advisories), rebuild images, and follow your distro or Kubernetes vendor guidance.

Use only on systems you are authorized to assess.

## References

- **CVE-2024-21626** — Leaky Vessels / `runc` (consult current vendor advisories and release notes for exact fixed versions and deployment steps).
