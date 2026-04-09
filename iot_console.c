/*
 * iot_console.c
 * =====================================================
 * Intro to cyber ops group project
 *
 * Vulnerabilities demonstrated:
 *   [1] Stack Buffer Overflow  — fgets() into an undersized stack buffer
 *   [2] Format String Leak     — printf() with a user-controlled format string
 *   [3] Use-After-Free (UAF)   — freed UserProfile chunk reclaimed by
 *                                PrivilegedConfig; write through dangling
 *                                active_profile pointer overwrites gate_key,
 *                                unlocking createShell()
 *
 * ── Compile (vulnerable) ───────────────────────────────────────────────────
 *   gcc -o iot_console iot_console.c \
 *       -no-pie -fno-stack-protector -g -O0
 *
 * ── Compile (hardened) ─────────────────────────────────────────────────────
 *   gcc -o iot_console iot_console.c \
 *       -fstack-protector-all -D_FORTIFY_SOURCE=2 \
 *       -pie -fPIE -Wformat -Wformat-security -O2
 *
 * ── Exploit walkthrough (UAF -> shell) ────────────────────────────────────
 *   Goal: get createShell() to spawn /bin/sh.
 *   shell_gate must equal GATE_UNLOCK_VAL (0x00C0FFEE) to pass the interlock.
 *
 *   Step 1 -- User Profile -> "Create profile"
 *            malloc(104) allocates UserProfile at address X.
 *
 *   Step 2 -- User Profile -> "Delete profile"
 *            free(X) -- active_profile is NOT nulled (UAF bug).
 *            Chunk X sits in glibc's tcache.
 *
 *   Step 3 -- Firmware Ops -> "Initialise firmware config"
 *            malloc(104) reclaims chunk X as PrivilegedConfig.
 *            active_profile (dangling) and priv_config now ALIAS each other:
 *              active_profile->username  (+0) == priv_config->gate_key (+0)
 *
 *   Step 4 -- User Profile -> "Edit username"
 *            fgets writes into active_profile->username at offset +0.
 *            Because of the alias this IS priv_config->gate_key.
 *            Input \xee\xff\xc0\x00 sets gate_key = 0x00C0FFEE.
 *            shell_gate is updated immediately.
 *
 *   Step 5 -- Admin Shell -> createShell() -> /bin/sh
 *
 * ── Mitigation notes ───────────────────────────────────────────────────────
 *   [1] Stack canary:   gcc -fstack-protector-all
 *   [2] Format safety:  printf("%s", user_input) -- never printf(user_input)
 *   [3] UAF fix:        set pointer to NULL immediately after free()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

/* ── Constants ──────────────────────────────────────────────────────────── */

#define GATE_UNLOCK_VAL  0x00C0FFEE

#define BANNER \
    "\n=================================================================\n" \
      "||    Random IoT Device Gateway -- Firmware vBlahBlah-release  ||\n" \
      "||    Management Console [User Mode RESTRICTED ACCESS]         ||\n" \
      "=================================================================\n"

/* ── Shell gate ─────────────────────────────────────────────────────────────
 * Hard-coded to 0xDEADBEEF (deny). Mimics real devices where developer-mode
 * operations are blocked until patched out by a privileged sequence.
 */
static volatile int shell_gate = 0xDEADBEEF;

/* ── Structs ─────────────────────────────────────────────────────────────────
 * Both structs are intentionally the same size (104 bytes) so that glibc's
 * tcache returns the freed UserProfile chunk to malloc(sizeof(PrivilegedConfig)).
 *
 * UserProfile -- 104 bytes
 *   +0   username[32]  <- UAF write lands here; overlaps gate_key at offset 0
 *   +32  email[48]
 *   +80  role[16]
 *   +96  uid   (int)
 *   +100 saved (int)
 *
 * PrivilegedConfig -- 104 bytes
 *   +0   gate_key (int)  <- same bytes as username[0..3] after heap reuse
 *   +4   device_id[32]
 *   +36  auth_hash[52]
 *   +88  access_level (int)
 *   +92  flags (int)
 *   +96  reserved[8]
 */
typedef struct {
    char username[32];
    char email[48];
    char role[16];
    int  uid;
    int  saved;
} UserProfile;           /* sizeof = 104 */

typedef struct {
    int  gate_key;
    char device_id[32];
    char auth_hash[52];
    int  access_level;
    int  flags;
    char reserved[8];
} PrivilegedConfig;      /* sizeof = 104 */

_Static_assert(sizeof(UserProfile) == sizeof(PrivilegedConfig),
               "Structs must be the same size for reliable tcache heap reuse");

static UserProfile      *active_profile = NULL;   /* becomes dangling after free! */
static PrivilegedConfig *priv_config    = NULL;

/* ── Utility helpers ────────────────────────────────────────────────────── */

static void flush_stdin(void)
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
        ;
}

static int read_int_choice(void)
{
    int choice;
    if (scanf("%d", &choice) != 1) {
        flush_stdin();
        return -1;
    }
    flush_stdin();
    return choice;
}

static void press_enter(void)
{
    printf("\nPress ENTER to continue...");
    flush_stdin();
}

/* ── createShell() ──────────────────────────────────────────────────────────
 * Common in embedded / IoT firmware ("recovery console", "debug shell").
 * Hard-coded to deny via shell_gate until the UAF chain sets it to
 * GATE_UNLOCK_VAL (0x00C0FFEE).
 */
static void createShell(void)
{
    printf("\n[*] Initialising security check...\n");
    printf("[*] shell_gate = 0x%08X\n", shell_gate);
    printf("[*] Expected   = 0x%08X\n", GATE_UNLOCK_VAL);

    if (shell_gate != GATE_UNLOCK_VAL) {
        printf("[!] ACCESS DENIED -- interlock engaged.\n");
        printf("[!] Shell spawn aborted.  Audit event logged.\n");
        return;
    }

    printf("[+] Spawning privileged shell...\n\n");
    system("/bin/sh");
}

static void menu_admin_shell(void)
{
    printf("\n+-- Admin Shell -------------------------------------------------+\n");
    printf("|  WARNING: Privileged hardware-level operation                  |\n");
    printf("|  Interlock must be released before access.                     |\n");
    printf("+----------------------------------------------------------------+\n");
    createShell();
    press_enter();
}

/* ── System Status (cosmetic) ───────────────────────────────────────────── */

static void menu_system_status(void)
{
    printf("\n+-- System Status -----------------------------------------------+\n");
    printf("| Model      : ACME-GW-4000                                      |\n");
    printf("| Firmware   : 2.3.1-release  (2024-11-01)                       |\n");
    printf("| Uptime     : 14d 07h 32m 11s                                   |\n");
    printf("| CPU load   : 3%% (1m)  12%% (5m)  8%% (15m)                   |\n");
    printf("| Free RAM   : 61440 KB / 131072 KB                              |\n");
    printf("| CPU temp   : 42 C                                              |\n");
    printf("| Flash      : 46%% used (58 MB / 128 MB)                        |\n");
    printf("| Watchdog   : ENABLED  (timeout: 30s)                           |\n");
    printf("| Status     : NOMINAL                                           |\n");
    printf("+----------------------------------------------------------------+\n");
    press_enter();
}

/* ── Network Configuration (cosmetic) ──────────────────────────────────── */

static void menu_network_config(void)
{
    int choice;
    printf("\n+-- Network Configuration ---------------------------------------+\n");
    printf("|  1. View current settings                                      |\n");
    printf("|  2. Set IP address                                             |\n");
    printf("|  3. Set default gateway                                        |\n");
    printf("|  4. Set DNS servers                                            |\n");
    printf("|  5. Configure VLAN                                             |\n");
    printf("|  6. Restart networking                                         |\n");
    printf("|  0. Back                                                       |\n");
    printf("+----------------------------------------------------------------+\n");
    printf("Choice: ");
    choice = read_int_choice();

    switch (choice) {
        case 1:
            printf("\n  Interface  : eth0\n");
            printf("  IPv4       : 192.168.1.1 / 24\n");
            printf("  Gateway    : 192.168.1.254\n");
            printf("  DNS        : 8.8.8.8, 1.1.1.1\n");
            printf("  MAC        : AA:BB:CC:DD:EE:FF\n");
            printf("  Duplex     : Full  Speed: 1000BASE-T\n");
            printf("  DHCP srv   : enabled (pool: .100-.200)\n");
            printf("  Firewall   : active (12 rules)\n");
            break;
        case 2: case 3: case 4: case 5: case 6:
            printf("  Feature not implemented in this build.\n");
            break;
        case 0: return;
        default: printf("[!] Invalid choice.\n");
    }
    press_enter();
}

/* ── User Profile Management ────────────────────────────────────────────────
 *
 * VULNERABILITY [3] -- Use-After-Free
 *
 * delete_profile() calls free(active_profile) but never nulls the pointer.
 * Once init_firmware_config() reclaims the same heap chunk as priv_config,
 * the two pointers alias:
 *
 *   active_profile->username  (offset +0) == priv_config->gate_key (offset +0)
 *
 * edit_profile() then writes user input through the dangling active_profile
 * pointer, landing directly in priv_config->gate_key.  Supplying the bytes
 * \xee\xff\xc0\x00 sets gate_key = 0x00C0FFEE and unlocks the shell.
 *
 * MITIGATION: active_profile = NULL; immediately after free().
 */

static void create_profile(void)
{
    if (active_profile) {
        printf("[!] A profile already exists in memory. Delete it first.\n");
        return;
    }
    active_profile = malloc(sizeof(UserProfile));
    if (!active_profile) { perror("malloc"); return; }
    memset(active_profile, 0, sizeof(UserProfile));

    printf("Username  : ");
    fgets(active_profile->username, sizeof(active_profile->username), stdin);
    active_profile->username[strcspn(active_profile->username, "\n")] = '\0';

    printf("Email     : ");
    fgets(active_profile->email, sizeof(active_profile->email), stdin);
    active_profile->email[strcspn(active_profile->email, "\n")] = '\0';

    printf("Role      : ");
    fgets(active_profile->role, sizeof(active_profile->role), stdin);
    active_profile->role[strcspn(active_profile->role, "\n")] = '\0';

    active_profile->uid   = 1000 + (rand() % 9000);
    active_profile->saved = 0;

    printf("[+] Profile created for '%s' (uid=%d) -- unsaved (memory only).\n",
           active_profile->username, active_profile->uid);
    printf("[*] UserProfile @ %p  (sizeof=%zu)\n",
           (void *)active_profile, sizeof(UserProfile));
}

static void view_profile(void)
{
    /*
     * UAF READ: if active_profile is dangling and priv_config now owns the
     * chunk, this leaks priv_config's raw bytes interpreted as profile fields.
     * Useful for observing the alias live.
     */
    if (!active_profile) {
        printf("[!] No profile in memory.\n");
        return;
    }
    printf("\n  Active User Profile\n");
    printf("  Addr    : %p\n",  (void *)active_profile);
    printf("  Username: %s\n",  active_profile->username);
    printf("  Email   : %s\n",  active_profile->email);
    printf("  Role    : %s\n",  active_profile->role);
    printf("  UID     : %d\n",  active_profile->uid);
    printf("  Saved   : %s\n",
           active_profile->saved ? "YES" : "NO (volatile -- memory only)");
}

static void edit_profile(void)
{
    /*
     * UAF WRITE -- the exploit primitive.
     *
     * After delete_profile() + init_firmware_config(), active_profile and
     * priv_config point to the same heap chunk.  Writing here at offset +0
     * sets priv_config->gate_key through the dangling pointer.
     *
     * Exploit input: \xee\xff\xc0\x00  -> gate_key = 0x00C0FFEE -> shell unlocked.
     */
    if (!active_profile) {
        printf("[!] No profile in memory (pointer is NULL).\n");
        return;
    }
    printf("[*] Profile @ %p  (may be dangling after delete!)\n",
           (void *)active_profile);
    printf("New username: ");
    fgets(active_profile->username, sizeof(active_profile->username), stdin);
    active_profile->username[strcspn(active_profile->username, "\n")] = '\0';
    printf("[+] Username updated.\n");

    /* If the alias is active, reflect gate_key change into shell_gate */
    if (priv_config && (void *)active_profile == (void *)priv_config) {
        shell_gate = priv_config->gate_key;
        printf("[*] Alias active: gate_key = 0x%08X  shell_gate = 0x%08X\n",
               priv_config->gate_key, shell_gate);
        if (shell_gate == GATE_UNLOCK_VAL)
            printf("[!!!] GATE UNLOCKED -- try Admin Shell now!\n");
    }
}

static void save_profile(void)
{
    if (!active_profile) {
        printf("[!] No profile in memory.\n");
        return;
    }
    active_profile->saved = 1;
    printf("[+] Profile '%s' committed to persistent storage.\n",
           active_profile->username);
}

static void delete_profile(void)
{
    if (!active_profile) {
        printf("[!] No profile in memory.\n");
        return;
    }
    printf("[*] Releasing heap memory for profile '%s' @ %p...\n",
           active_profile->username, (void *)active_profile);
    free(active_profile);

    /*
     * BUG [3]: pointer NOT nulled after free().
     * active_profile is now dangling -- any dereference is UAF.
     *
     * MITIGATION: active_profile = NULL;
     */
    printf("[+] free() called.  Pointer NOT nulled -- UAF window open.\n");
    printf("[!] active_profile still holds stale address %p\n",
           (void *)active_profile);
}

static void menu_user_profile(void)
{
    int choice;
    for (;;) {
        printf("\n+-- User Profile Management ------------------------------------+\n");
        printf("|  1. Create profile                                           |\n");
        printf("|  2. View profile              (UAF read risk)                |\n");
        printf("|  3. Edit username             [UAF WRITE]                    |\n");
        printf("|  4. Save profile to storage                                  |\n");
        printf("|  5. Delete profile  free()    [OPENS UAF WINDOW]             |\n");
        printf("|  0. Back                                                     |\n");
        printf("+--------------------------------------------------------------+\n");
        printf("Choice: ");
        choice = read_int_choice();
        switch (choice) {
            case 1: create_profile(); break;
            case 2: view_profile();   break;
            case 3: edit_profile();   break;
            case 4: save_profile();   break;
            case 5: delete_profile(); break;
            case 0: return;
            default: printf("[!] Invalid choice.\n");
        }
        press_enter();
    }
}

/* ── Diagnostic Tools ───────────────────────────────────────────────────────
 *
 * VULNERABILITY [1] -- Stack Buffer Overflow  (write_diag_log)
 *
 *   log_msg is 32 bytes on the stack.  fgets() is called with limit 128,
 *   so > 31 chars overflows the buffer, corrupting the saved return address.
 *
 *   MITIGATION -- Stack canary (gcc -fstack-protector-all):
 *     A random value is placed between the buffer and the return address.
 *     Overflow clobbers it; __stack_chk_fail() fires before RIP is used.
 *   MITIGATION -- Code fix: fgets(log_msg, sizeof(log_msg), stdin);
 *
 * VULNERABILITY [2] -- Format String Leak  (run_ping_test)
 *
 *   User input is passed directly as printf's format string.
 *   "%p %p %p %p %p" leaks stack addresses; "%n" writes to a stack pointer.
 *
 *   MITIGATION: printf("%s\n", host);  -- always use a literal format string.
 */

static void write_diag_log(void)
{
    char log_msg[32];   /* 32 bytes on the stack */

    printf("\n  [VULN 1: Stack Buffer Overflow]\n");
    printf("  Buffer on stack : %zu bytes\n", sizeof(log_msg));
    printf("  fgets limit     : 128 bytes  <- MISMATCH\n");
    printf("  Mitigation      : -fstack-protector-all  (stack canary)\n\n");

    printf("Enter diagnostic message: ");
    fgets(log_msg, 128, stdin);   /* reads up to 128 bytes into 32-byte buffer */
    printf("[LOG] %s\n", log_msg);
}

static void run_ping_test(void)
{
    char host[128];

    printf("\n  [VULN 2: Format String Leak]\n");
    printf("  printf() called with user input as the format string.\n");
    printf("  Try: %%p %%p %%p %%p %%p  to leak stack addresses.\n");
    printf("  Mitigation: printf(\"%%s\", host)  -- literal format string.\n\n");

    printf("Enter target host / IP: ");
    fgets(host, sizeof(host), stdin);
    host[strcspn(host, "\n")] = '\0';

    printf("\nResult for: ");
    printf(host);            /* FORMAT STRING VULNERABILITY */
    printf("\n  ICMP ping not available -- 3/3 packets simulated OK\n");
}

static void view_interface_stats(void)
{
    printf("\n  Interface statistics (eth0)\n");
    printf("  -----------------------------------------\n");
    printf("  RX packets : 1,482,931   bytes: 2,047,183,612\n");
    printf("  TX packets :   983,204   bytes:   847,293,048\n");
    printf("  Errors     :         0   Dropped:           12\n");
    printf("  Collisions :         0\n");
    printf("  MTU        :      1500   Queue len:        1000\n");
}

static void view_cpu_profile(void)
{
    printf("\n  CPU process profile (top 5)\n");
    printf("  -----------------------------------------\n");
    printf("  PID   %%CPU  %%MEM  CMD\n");
    printf("   341   2.1   0.8  /sbin/gateway-daemon\n");
    printf("   512   0.4   0.3  /usr/sbin/sshd\n");
    printf("   601   0.2   0.1  /sbin/watchdogd\n");
    printf("   702   0.1   0.1  /usr/bin/iot_console\n");
    printf("     1   0.0   0.0  /sbin/init\n");
}

static void menu_diagnostics(void)
{
    int choice;
    for (;;) {
        printf("\n+-- Diagnostic Tools -------------------------------------------+\n");
        printf("|  1. Write diagnostic log    [STACK OVERFLOW]                 |\n");
        printf("|  2. Ping / connectivity test [FORMAT STR LEAK]               |\n");
        printf("|  3. Interface statistics                                     |\n");
        printf("|  4. CPU process profile                                      |\n");
        printf("|  0. Back                                                     |\n");
        printf("+--------------------------------------------------------------+\n");
        printf("Choice: ");
        choice = read_int_choice();
        switch (choice) {
            case 1: write_diag_log();       break;
            case 2: run_ping_test();        break;
            case 3: view_interface_stats(); break;
            case 4: view_cpu_profile();     break;
            case 0: return;
            default: printf("[!] Invalid choice.\n");
        }
        press_enter();
    }
}

/* ── Firmware Operations ────────────────────────────────────────────────────
 *
 * init_firmware_config() is the second half of the UAF chain.
 *
 * malloc(sizeof(PrivilegedConfig)) == malloc(104).  If UserProfile was freed
 * beforehand, glibc's tcache hands back the exact same chunk.
 * active_profile (dangling) and priv_config then alias each other, making
 * the edit_profile() UAF write meaningful.
 */

static void init_firmware_config(void)
{
    if (priv_config) {
        printf("[*] Firmware config already initialised @ %p\n",
               (void *)priv_config);
        printf("[*] gate_key = 0x%08X\n", priv_config->gate_key);
        return;
    }

    priv_config = malloc(sizeof(PrivilegedConfig));
    if (!priv_config) { perror("malloc"); return; }
    memset(priv_config, 0, sizeof(PrivilegedConfig));

    priv_config->gate_key     = 0xDEADBEEF;   /* locked */
    priv_config->access_level = 0;
    priv_config->flags        = 0x00000001;
    snprintf(priv_config->device_id, sizeof(priv_config->device_id),
             "ACME-GW4K-SN%06d", rand() % 999999);

    printf("[+] Firmware config initialised.\n");
    printf("[*] priv_config @ %p  sizeof=%zu\n",
           (void *)priv_config, sizeof(PrivilegedConfig));
    printf("[*] gate_key    = 0x%08X  (locked)\n", priv_config->gate_key);
    printf("[*] device_id   = %s\n", priv_config->device_id);

    /* Alias detection */
    if (active_profile != NULL) {
        printf("[*] active_profile @ %p  (dangling after delete?)\n",
               (void *)active_profile);
        if ((void *)active_profile == (void *)priv_config) {
            printf("[!!!] ALIAS CONFIRMED: active_profile == priv_config\n");
            printf("[!!!] UAF window ACTIVE -- edit username to overwrite gate_key!\n");
        }
    }
}

static void check_firmware_update(void)
{
    printf("[*] Contacting update server at firmware.acme-iot.local...\n");
    sleep(1);
    printf("[*] Current   : 2.3.1-release  (2024-11-01)\n");
    printf("[*] Available : 2.3.1-release  -- no update required.\n");
    printf("[*] Signature : VALID  (RSA-2048)\n");
}

static void verify_firmware_hash(void)
{
    printf("[*] Computing SHA-256 of /dev/mtd0 (flash partition)...\n");
    sleep(1);
    printf("[*] Stored   : a3f1c2b4d9e08716fa2c31b845eca29d01f7c580e3d6a89b12345678deadbeef\n");
    printf("[*] Computed : a3f1c2b4d9e08716fa2c31b845eca29d01f7c580e3d6a89b12345678deadbeef\n");
    printf("[+] Firmware integrity: OK\n");
}

static void menu_firmware(void)
{
    int choice;
    for (;;) {
        printf("\n+-- Firmware Operations ----------------------------------------+\n");
        printf("|  1. Initialise firmware config  [UAF heap alias]             |\n");
        printf("|  2. Check for updates                                        |\n");
        printf("|  3. Verify firmware hash                                     |\n");
        printf("|  0. Back                                                     |\n");
        printf("+--------------------------------------------------------------+\n");
        printf("Choice: ");
        choice = read_int_choice();
        switch (choice) {
            case 1: init_firmware_config();  break;
            case 2: check_firmware_update(); break;
            case 3: verify_firmware_hash();  break;
            case 0: return;
            default: printf("[!] Invalid choice.\n");
        }
        press_enter();
    }
}

/* ── Security Audit Log (cosmetic) ─────────────────────────────────────── */

static void menu_audit_log(void)
{
    printf("\n+-- Security Audit Log -------------------------------------------------+\n");
    printf("| Timestamp            | User     | Event                  | Result     |\n");
    printf("+----------------------+----------+------------------------+------------+\n");
    printf("| 2024-11-01 08:14:02  | admin    | Console login          | SUCCESS    |\n");
    printf("| 2024-11-01 09:22:18  | admin    | Firmware check         | UP-TO-DATE |\n");
    printf("| 2024-11-01 11:05:44  | admin    | Admin shell request    | DENIED     |\n");
    printf("| 2024-11-01 13:10:09  | sysmon   | Config backup          | SUCCESS    |\n");
    printf("| 2024-11-01 14:37:09  | admin    | Network config view    | SUCCESS    |\n");
    printf("| 2024-11-01 17:58:33  | admin    | Console logout         | SUCCESS    |\n");
    printf("| 2024-11-02 00:00:00  | system   | Log rotation           | SUCCESS    |\n");
    printf("| 2024-11-02 06:44:21  | sysmon   | Watchdog heartbeat     | OK         |\n");
    printf("| 2024-11-02 14:19:55  | admin    | Admin shell request    | DENIED     |\n");
    printf("+-----------------------------------------------------------------------+\n");
    press_enter();
}

/* ── Certificate & Key Management (cosmetic) ────────────────────────────── */

static void menu_cert_mgmt(void)
{
    int choice;
    printf("\n+-- Certificate & Key Management --------------------------------+\n");
    printf("|  1. View TLS certificate                                       |\n");
    printf("|  2. Renew certificate                                          |\n");
    printf("|  3. View trusted CA list                                       |\n");
    printf("|  0. Back                                                       |\n");
    printf("+----------------------------------------------------------------+\n");
    printf("Choice: ");
    choice = read_int_choice();
    if (choice == 1) {
        printf("\n  Subject : CN=ACME-GW-4000, O=ACME Corp, C=US\n");
        printf("  Issuer  : CN=ACME Internal CA\n");
        printf("  Serial  : 0x3A9F1C7B\n");
        printf("  Valid   : 2024-01-01  --  2025-01-01\n");
        printf("  SAN     : 192.168.1.1, gateway.local\n");
        printf("  Algo    : RSA 2048 / SHA-256\n");
        printf("  Status  : VALID\n");
    } else if (choice != 0) {
        printf("  Not implemented in this build.\n");
    }
    press_enter();
}

/* ── Main Menu ──────────────────────────────────────────────────────────── */

static void main_menu(void)
{
    int choice;
    for (;;) {
        printf(BANNER);
        printf("  1.  System Status\n");
        printf("  2.  Network Configuration\n");
        printf("  3.  User Profile Management\n");
        printf("  4.  Diagnostic Tools\n");
        printf("  5.  Firmware Operations\n");
        printf("  6.  Security Audit Log\n");
        printf("  7.  Certificate & Key Management\n");
        printf("  8.  Admin Shell\n");
        printf("  0.  Exit\n");
        printf("\nSelect: ");

        choice = read_int_choice();
        switch (choice) {
            case 1: menu_system_status();  break;
            case 2: menu_network_config(); break;
            case 3: menu_user_profile();   break;
            case 4: menu_diagnostics();    break;
            case 5: menu_firmware();       break;
            case 6: menu_audit_log();      break;
            case 7: menu_cert_mgmt();      break;
            case 8: menu_admin_shell();    break;
            case 0:
                printf("Closing console session.  Goodbye.\n");
                if (priv_config) { free(priv_config); priv_config = NULL; }
                exit(0);
            default:
                printf("[!] Invalid selection.\n");
        }
    }
}

/* ── Entry point ────────────────────────────────────────────────────────── */

int main(void)
{
    srand((unsigned)time(NULL));
    setbuf(stdout, NULL);
    main_menu();
    return 0;
}