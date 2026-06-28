# DirtyClone

DirtyClone is a C-based local privilege escalation (LPE) proof-of-concept targeting a kernel/XFRM-related vulnerability described in the source as CVE-2026-43503. The program is intended for authorized security research and testing in controlled environments only.

## Overview

This repository contains a single source file:

- [dirtyclone.c](dirtyclone.c) – the exploit implementation written in C

The program performs a sequence of steps intended to:

- create isolated user and network namespaces,
- configure loopback and XFRM/IPsec-related networking state,
- build an ESP packet using AES-CBC encryption,
- trigger a page-cache patching flow against the target SUID binary,
- execute the patched target binary.

## Important notice

This tool is designed for authorized security testing only. Running it against systems without explicit permission may be illegal and can cause serious security and system integrity issues.

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

Then compile the program with:

```bash
gcc -o dirtyclone dirtyclone.c -lcrypto -Wall -O2
```

## Usage

Run the binary with:

```bash
./dirtyclone
```

Optional flags:

```bash
./dirtyclone -q    # quiet mode
./dirtyclone -v    # verbose mode (default)
./dirtyclone -h    # show help
```

## What the program does

At a high level, the program:

1. Displays a banner and checks whether it is already running as root.
2. Verifies basic runtime prerequisites such as the target SUID binary path and architecture support.
3. Sets up namespaces and loopback networking.
4. Configures XFRM state/policy and a TEE netfilter rule.
5. Maps the target SUID binary into memory and prepares an ESP packet.
6. Sends the crafted packet and waits for the page cache to reflect the patched bytes.
7. Executes the target binary, which is expected to result in a privileged shell.

## Technical details

The implementation includes:

- adaptive retry logic for waiting on page-cache changes,
- cleanup routines registered via `atexit` and signal handlers,
- secure process execution using `fork` and `execvp`,
- AES-CBC encryption using OpenSSL EVP APIs,
- architecture-aware shellcode for x86_64 and AArch64 systems.

## Prerequisites

The source expects a Linux environment with:

- GCC/Clang toolchain,
- OpenSSL development headers/libraries,
- `ip`, `iptables`, and `modprobe` available on the system,
- a compatible kernel and target binary at `/usr/bin/su`.

## Safety and ethics

Use this project only in the following circumstances:

- you own the target system,
- you have explicit authorization to test it,
- you are operating in a lab or isolated environment.

Never deploy or run this code on production systems or systems you do not have permission to assess.

## License and authorship

The source header identifies the author as MrAashish0x1 (gl1tch0x1). The repository does not include a separate license file, so the code should be treated as research material rather than production software.
