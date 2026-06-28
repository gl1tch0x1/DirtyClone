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

## How DirtyClone works

The exploit is built around a simple idea: the program prepares a crafted ESP/XFRM payload that causes the kernel to decrypt data into a page-cache-backed region of memory, then checks whether the bytes in the target SUID binary have changed.

In practical terms, the program performs the following actions:

- identifies a target file, `/usr/bin/su`, and maps it into memory;
- prepares a small payload containing shellcode bytes and the necessary ESP metadata;
- encrypts the payload with AES-CBC so it can be fed into the XFRM/ESP path;
- sends the packet through the local network stack using either TEE-assisted UDP or a raw IP fallback;
- monitors the mapped region for the expected bytes to appear;
- if the bytes appear, it assumes the exploit path has altered the page cache and executes the patched target path.

This is a proof-of-concept flow, not a general-purpose privilege escalation framework. It is intended to demonstrate the exploit mechanism and to help verify whether a target kernel still exposes the vulnerable behavior.

## Dummy implementation example

The following simplified example shows the same concept at a high level:

```c
#include <stdio.h>
#include <string.h>

static int dummy_exploit(unsigned char *target_bytes) {
    unsigned char expected[] = {0x31, 0x0f, 0x05};
    memcpy(target_bytes, expected, sizeof(expected));
    return 0;
}

int main(void) {
    unsigned char target[16] = {0};
    dummy_exploit(target);
    printf("Patched bytes: %02x %02x %02x\n", target[0], target[1], target[2]);
    return 0;
}
```

The real project uses the same principle, but it packages the payload as an ESP/XFRM-style packet and drives the kernel path through the networking stack instead of a simple memory copy.

## Exploitation walkthrough

1. Setup phase
   - the program creates namespaces to isolate the process environment;
   - it configures loopback networking so packets stay local.

2. XFRM preparation
   - the exploit adds XFRM states and policies that tell the kernel how to process ESP traffic;
   - it also attempts to install a TEE rule so traffic can be redirected through the planned path.

3. Payload construction
   - the code builds a small plaintext payload containing shellcode-style bytes;
   - the payload is encrypted with AES-CBC using a static test key.

4. Delivery phase
   - the program sends the crafted ESP packet over UDP or raw IP;
   - the kernel processes the packet and, on a vulnerable system, writes the decrypted data back into the page cache region of the target binary.

5. Verification and execution
   - the code watches the target file’s bytes and checks whether they match the expected shellcode bytes;
   - if they do, it attempts to execute the target binary and hand control to the injected payload path.

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
