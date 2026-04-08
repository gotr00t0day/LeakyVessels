# LeakyVessels

This tool checks whether the host’s **`runc`** version is in the range affected by **CVE-2024-21626** (“Leaky Vessels”). That class of issues can, under the right conditions, weaken container isolation with respect to the host filesystem—so knowing if you are still on a vulnerable runtime matters for patching and image rebuilds.

## What it does

- Looks for `runc` in common paths (`/usr/bin/runc`, `/usr/local/sbin/runc`, `/usr/sbin/runc`) or on `PATH` via `which`.
- If found, runs `runc --version` and parses the reported version string.
- Compares the version to the tool’s internal threshold: runc **before 1.1.12** is treated as **vulnerable**; **1.1.12 and newer** as not vulnerable (for normal `X.Y.Z` style versions).

## Requirements

- A system where `runc` may be installed (typical: Linux nodes running containers with runc as the low-level runtime).
- C++17 or newer (`std::filesystem`); the project uses **C++20** in other targets—using C++20 here matches the rest of the repo.
- POSIX-style `popen` / `system` (Linux, etc.).

## Build (standalone)

```bash
g++ leakyvessels.cpp -o leakyvessels -std=c++20 -pthread
```

## Limitations

- **Version parsing** expects dot-separated numeric components (e.g. `1.1.11`). Unusual vendor suffixes or non-numeric segments can break `parse_version` or give misleading results.
- **Presence of `runc` on disk** does not mean every workload uses it (e.g. other runtimes may be default). This tool only reflects the `runc` binary it finds.
- **Remediation** is operational: upgrade `runc` to a fixed release (e.g. **≥ 1.1.12** per upstream advisories), rebuild images, and follow your distro or Kubernetes vendor guidance.

Use only on systems you are authorized to assess.

## References

- **CVE-2024-21626** — Leaky Vessels / `runc` (consult current vendor advisories and release notes for exact fixed versions and deployment steps).
- https://www.wiz.io/blog/leaky-vessels-container-escape-vulnerabilities
