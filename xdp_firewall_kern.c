typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800 
#define MAX_RULES 1024
#define MAX_BLOCKED_IPS 1024

// Структура для правил фильтрации
struct rule {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 action;
    __u8 enabled;
    __u8 reserved;
};

// Структура для статистики
struct stats {
    __u64 packets_processed;
    __u64 packets_dropped;
    __u64 packets_passed;
    __u64 bytes_processed;
};

// BPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rule);
    __uint(max_entries, MAX_RULES);
} rules_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, MAX_BLOCKED_IPS);
} blocked_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct stats);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

// Проверка IP в блок-листе
static __always_inline int is_ip_blocked(__u32 ip) {
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &ip);
    return blocked ? 1 : 0;
}

// Обновление статистики
static __always_inline void update_stats(__u64 bytes, int dropped) {
    __u32 key = 0;
    struct stats *stat = bpf_map_lookup_elem(&stats_map, &key);
    if (stat) {
        __sync_fetch_and_add(&stat->packets_processed, 1);
        __sync_fetch_and_add(&stat->bytes_processed, bytes);
        if (dropped) {
            __sync_fetch_and_add(&stat->packets_dropped, 1);
        } else {
            __sync_fetch_and_add(&stat->packets_passed, 1);
        }
    }
}

// Проверка правил
static __always_inline int check_rules(__u32 src_ip, __u32 dst_ip, 
                                      __u16 src_port, __u16 dst_port, 
                                      __u8 protocol) {
#pragma unroll
    for (int i = 0; i < 32; i++) { 
        __u32 key = i;
        struct rule *rule = bpf_map_lookup_elem(&rules_map, &key);
        if (!rule || !rule->enabled)
            continue;

        if ((rule->src_ip == 0 || rule->src_ip == src_ip) &&
            (rule->dst_ip == 0 || rule->dst_ip == dst_ip) &&
            (rule->src_port == 0 || rule->src_port == src_port) &&
            (rule->dst_port == 0 || rule->dst_port == dst_port) &&
            (rule->protocol == 0 || rule->protocol == protocol)) {
            return rule->action;
        }
    }

    return XDP_PASS;
}

SEC("xdp")
int xdp_firewall_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;

    __u32 src_ip = 0, dst_ip = 0;
    __u16 src_port = 0, dst_port = 0;
    __u8 protocol = 0;
    __u64 packet_size = data_end - data;

    if ((void *)(eth + 1) > data_end)
        goto pass;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        goto pass;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        goto pass;

    if ((void *)ip + (ip->ihl * 4) > data_end)
        goto pass;

    src_ip = bpf_ntohl(ip->saddr);
    dst_ip = bpf_ntohl(ip->daddr);
    protocol = ip->protocol;

    if (is_ip_blocked(src_ip)) {
        update_stats(packet_size, 1);
        return XDP_DROP;
    }

    switch (protocol) {
        case IPPROTO_TCP:
            tcp = (void *)ip + (ip->ihl * 4);
            if ((void *)(tcp + 1) > data_end)
                goto pass;
            src_port = bpf_ntohs(tcp->source);
            dst_port = bpf_ntohs(tcp->dest);
            break;

        case IPPROTO_UDP:
            udp = (void *)ip + (ip->ihl * 4);
            if ((void *)(udp + 1) > data_end)
                goto pass;
            src_port = bpf_ntohs(udp->source);
            dst_port = bpf_ntohs(udp->dest);
            break;

        case IPPROTO_ICMP:
            break;

        default:
            goto pass;
    }

    int action = check_rules(src_ip, dst_ip, src_port, dst_port, protocol);

    if (action == 0) {
        update_stats(packet_size, 1);
        return XDP_DROP;
    }

pass:
    update_stats(packet_size, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
