#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_RULES 1024
#define MAX_BLOCKED_IPS 1024

// Структура для правил фильтрации
struct rule {
    __u32 src_ip;        // Source IP (0 = any)
    __u32 dst_ip;        // Destination IP (0 = any)
    __u16 src_port;      // Source port (0 = any)
    __u16 dst_port;      // Destination port (0 = any)
    __u8 protocol;       // Protocol (0 = any, 6 = TCP, 17 = UDP, 1 = ICMP)
    __u8 action;         // 0 = DROP, 1 = PASS
    __u8 enabled;        // 1 = enabled, 0 = disabled
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

// Функция для проверки IP в блек-листе
static __always_inline int is_ip_blocked(__u32 ip) {
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &ip);
    return blocked ? 1 : 0;
}

// Функция для обновления статистики
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

// Функция для проверки правил
static __always_inline int check_rules(__u32 src_ip, __u32 dst_ip, 
                                      __u16 src_port, __u16 dst_port, 
                                      __u8 protocol) {
    struct rule *rule;
    __u32 key;
    
    // Проверяем все правила
    for (key = 0; key < MAX_RULES; key++) {
        rule = bpf_map_lookup_elem(&rules_map, &key);
        if (!rule || !rule->enabled)
            continue;
            
        // Проверяем соответствие правилу
        if ((rule->src_ip == 0 || rule->src_ip == src_ip) &&
            (rule->dst_ip == 0 || rule->dst_ip == dst_ip) &&
            (rule->src_port == 0 || rule->src_port == src_port) &&
            (rule->dst_port == 0 || rule->dst_port == dst_port) &&
            (rule->protocol == 0 || rule->protocol == protocol)) {
            
            // Правило совпало
            return rule->action; // 0 = DROP, 1 = PASS
        }
    }
    
    // По умолчанию пропускаем
    return XDP_PASS;
}

SEC("xdp_firewall")
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
    
    // Проверяем границы для Ethernet заголовка
    if ((void *)(eth + 1) > data_end)
        goto pass;
    
    // Обрабатываем только IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        goto pass;
    
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        goto pass;
    
    src_ip = bpf_ntohl(ip->saddr);
    dst_ip = bpf_ntohl(ip->daddr);
    protocol = ip->protocol;
    
    // Быстрая проверка заблокированных IP
    if (is_ip_blocked(src_ip)) {
        update_stats(packet_size, 1);
        return XDP_DROP;
    }
    
    // Извлекаем порты в зависимости от протокола
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
            // ICMP не имеет портов
            break;
            
        default:
            goto pass;
    }
    
    // Проверяем правила
    int action = check_rules(src_ip, dst_ip, src_port, dst_port, protocol);
    
    if (action == 0) { // DROP
        update_stats(packet_size, 1);
        return XDP_DROP;
    }
    
pass:
    update_stats(packet_size, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
