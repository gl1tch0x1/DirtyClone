# DirtyClone

DirtyClone is a diagnostic, proof-of-concept local privilege escalation tool written in C. It targets a kernel/XFRM-related exploit path described in the source as CVE-2026-43503 and is intended only for authorized security research in controlled environments.

## Overview

This repository contains:

- [dirtyclone.c](dirtyclone.c) – the full exploit implementation
- [README.md](README.md) – usage and environment guidance

The current implementation performs the following high-level steps:

- creates isolated user and network namespaces,
- configures loopback networking and XFRM/IPsec state/policies,
- builds an ESP payload using AES-CBC encryption,
- attempts delivery through a TEE-based UDP path and a raw IP fallback,
- waits for the target SUID binary’s page cache to be patched,
- executes the target binary if the page cache is modified.

## Important notice

This tool is intended for authorized security testing only. Running it on systems without explicit permission can be illegal and may impact system integrity.

## Build

Install the required OpenSSL development package first:

```bash
# Debian/Ubuntu
sudo apt-get install libssl-dev

# Fedora
sudo dnf install openssl-devel

# Arch Linux
sudo pacman -S openssl
```

Then compile the binary:

```bash
gcc -o dirtyclone dirtyclone.c -lcrypto -Wall -O2
```

## Usage

Run the program with:

```bash
./dirtyclone
```

Optional arguments:

```bash
./dirtyclone -q    # quiet mode
./dirtyclone -v    # verbose mode (default)
./dirtyclone -h    # show help
```

## What the program does

At runtime the program:

1. prints a banner and checks whether it is already running as root;
2. verifies kernel and architecture details and reports whether the system appears to match the vulnerable range;
3. sets up namespaces and loopback networking;
4. configures XFRM state/policies and attempts to add a TEE netfilter rule;
5. maps the target SUID binary into memory and prints a PoC summary of the original vs expected bytes;
6. sends an ESP packet using either UDP+TEE or a raw IP fallback;
7. waits for the page cache to reflect the injected bytes and then attempts to execute the target binary.

## Technical details

The implementation includes:

- adaptive retry logic while waiting for page-cache changes,
- cleanup routines registered via `atexit` and signal handlers,
- `fork`/`execvp`-based secure command execution,
- AES-CBC encryption using OpenSSL EVP APIs,
- architecture-aware shellcode for x86_64 and AArch64,
- dual delivery logic for both TEE-assisted UDP and raw IP transport.

## Prerequisites

The source expects a Linux environment with:

- GCC or Clang,
- OpenSSL development headers and libraries,
- `ip`, `iptables`, and `modprobe` available on the system,
- a target binary at `/usr/bin/su`,
- a kernel that may be vulnerable to the described exploit path.

## Expected behavior

The program is intended to show a diagnostic PoC summary and then either:

- successfully patch the page cache and execute the target binary, or
- fail cleanly if the kernel is patched or the exploit path is not available.

If the exploit does not trigger, the program prints a clear message suggesting that the kernel is likely patched.

## Safety and ethics

Use this project only when:

- you own the target system,
- you have explicit authorization to test it,
- you are operating in a lab or isolated environment.

Never run this code on production systems or systems you do not have permission to assess.

## License and authorship

The source header identifies the author as MrAashish0x1 (gl1tch0x1). The repository does not include a separate license file, so the code should be treated as research material rather than production software.
