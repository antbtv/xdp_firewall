#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAX_RULES 1024
#define MAX_BLOCKED_IPS 1024

// Структуры должны совпадать с ядерными
struct rule {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t action;
    uint8_t enabled;
    uint8_t reserved;
};

struct stats {
    uint64_t packets_processed;
    uint64_t packets_dropped;
    uint64_t packets_passed;
    uint64_t bytes_processed;
};

static int rules_map_fd = -1;
static int blocked_ips_fd = -1;
static int stats_map_fd = -1;
static int prog_fd = -1;
static int ifindex = -1;

static void cleanup() {
    if (ifindex > 0 && prog_fd > 0) {
        printf("Отключаем XDP программу от интерфейса...\n");
        bpf_xdp_detach(ifindex, 0, NULL);
    }
}

static void signal_handler(int sig) {
    cleanup();
    exit(0);
}

// Функция для конвертации IP строки в число
static uint32_t ip_to_int(const char *ip_str) {
    struct in_addr addr;
    if (inet_aton(ip_str, &addr) == 0) {
        return 0;
    }
    return ntohl(addr.s_addr);
}

// Функция для добавления правила
static int add_rule(uint32_t rule_id, const char *src_ip, const char *dst_ip,
                   uint16_t src_port, uint16_t dst_port, uint8_t protocol, uint8_t action) {
    struct rule rule = {0};
    
    if (rule_id >= MAX_RULES) {
        printf("Ошибка: ID правила превышает максимум (%d)\n", MAX_RULES);
        return -1;
    }
    
    rule.src_ip = src_ip ? ip_to_int(src_ip) : 0;
    rule.dst_ip = dst_ip ? ip_to_int(dst_ip) : 0;
    rule.src_port = src_port;
    rule.dst_port = dst_port;
    rule.protocol = protocol;
    rule.action = action;
    rule.enabled = 1;
    
    if (bpf_map_update_elem(rules_map_fd, &rule_id, &rule, BPF_ANY) != 0) {
        printf("Ошибка добавления правила: %s\n", strerror(errno));
        return -1;
    }
    
    printf("Правило %d добавлено успешно\n", rule_id);
    return 0;
}

// Функция для блокировки IP
static int block_ip(const char *ip_str) {
    uint32_t ip = ip_to_int(ip_str);
    uint8_t blocked = 1;
    
    if (ip == 0) {
        printf("Ошибка: некорректный IP адрес\n");
        return -1;
    }
    
    if (bpf_map_update_elem(blocked_ips_fd, &ip, &blocked, BPF_ANY) != 0) {
        printf("Ошибка блокировки IP: %s\n", strerror(errno));
        return -1;
    }
    
    printf("IP %s заблокирован\n", ip_str);
    return 0;
}

// Функция для показа статистики
static void show_stats() {
    uint32_t key = 0;
    struct stats stat;
    
    if (bpf_map_lookup_elem(stats_map_fd, &key, &stat) == 0) {
        printf("\n=== Статистика Firewall ===\n");
        printf("Обработано пакетов: %lu\n", stat.packets_processed);
        printf("Заблокировано пакетов: %lu\n", stat.packets_dropped);
        printf("Пропущено пакетов: %lu\n", stat.packets_passed);
        printf("Обработано байт: %lu\n", stat.bytes_processed);
        if (stat.packets_processed > 0) {
            printf("Процент блокировки: %.2f%%\n", 
                   (double)stat.packets_dropped * 100.0 / stat.packets_processed);
        }
        printf("===========================\n\n");
    }
}

static void print_usage(const char *prog_name) {
    printf("Использование: %s <интерфейс> [команды]\n\n", prog_name);
    printf("Команды:\n");
    printf("  -r <id> <src_ip> <dst_ip> <src_port> <dst_port> <protocol> <action>\n");
    printf("     Добавить правило (используйте 0 для 'любой')\n");
    printf("     protocol: 0=любой, 1=ICMP, 6=TCP, 17=UDP\n");
    printf("     action: 0=DROP, 1=PASS\n");
    printf("  -b <ip>  Заблокировать IP адрес\n");
    printf("  -s       Показать статистику\n");
    printf("  -d       Демон режим (мониторинг)\n\n");
    printf("Примеры:\n");
    printf("  %s eth0 -r 1 0 0 0 22 6 0    # Блокировать SSH на порт 22\n", prog_name);
    printf("  %s eth0 -r 2 192.168.1.100 0 0 0 0 1  # Разрешить трафик с IP\n", prog_name);
    printf("  %s eth0 -b 192.168.1.200    # Заблокировать IP\n", prog_name);
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int err;
    
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    char *interface = argv[1];
    ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        printf("Ошибка: интерфейс %s не найден\n", interface);
        return 1;
    }
    
    // Увеличиваем лимит памяти для BPF
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        printf("Ошибка установки лимита памяти\n");
        return 1;
    }
    
    // Загружаем BPF программу
    obj = bpf_object__open_file("xdp_firewall_kern.o", NULL);
    if (libbpf_get_error(obj)) {
        printf("Ошибка открытия BPF объекта\n");
        return 1;
    }
    
    err = bpf_object__load(obj);
    if (err) {
        printf("Ошибка загрузки BPF объекта: %d\n", err);
        return 1;
    }
    
    // Получаем программу и карты
    prog = bpf_object__find_program_by_name(obj, "xdp_firewall_prog");
    if (!prog) {
        printf("Ошибка: программа xdp_firewall_prog не найдена\n");
        return 1;
    }
    
    prog_fd = bpf_program__fd(prog);
    rules_map_fd = bpf_object__find_map_fd_by_name(obj, "rules_map");
    blocked_ips_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
    stats_map_fd = bpf_object__find_map_fd_by_name(obj, "stats_map");
    
    if (rules_map_fd < 0 || blocked_ips_fd < 0 || stats_map_fd < 0) {
        printf("Ошибка получения файловых дескрипторов карт\n");
        return 1;
    }
    
    // Присоединяем программу к интерфейсу
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        printf("Ошибка присоединения XDP программы к %s: %d\n", interface, err);
        printf("Попробуйте запустить с правами root\n");
        return 1;
    }
    
    printf("XDP Firewall успешно загружен на интерфейс %s\n", interface);
    
    // Устанавливаем обработчик сигналов
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Обрабатываем аргументы командной строки
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0 && i + 7 < argc) {
            // Добавить правило
            uint32_t rule_id = atoi(argv[i+1]);
            char *src_ip = strcmp(argv[i+2], "0") ? argv[i+2] : NULL;
            char *dst_ip = strcmp(argv[i+3], "0") ? argv[i+3] : NULL;
            uint16_t src_port = atoi(argv[i+4]);
            uint16_t dst_port = atoi(argv[i+5]);
            uint8_t protocol = atoi(argv[i+6]);
            uint8_t action = atoi(argv[i+7]);
            
            add_rule(rule_id, src_ip, dst_ip, src_port, dst_port, protocol, action);
            i += 7;
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            // Заблокировать IP
            block_ip(argv[i+1]);
            i++;
        } else if (strcmp(argv[i], "-s") == 0) {
            // Показать статистику
            show_stats();
        } else if (strcmp(argv[i], "-d") == 0) {
            // Демон режим
            printf("Запущен режим мониторинга. Нажмите Ctrl+C для выхода.\n");
            while (1) {
                sleep(5);
                show_stats();
            }
        }
    }
    
    if (argc == 2) {
        printf("Firewall активен. Используйте -h для справки по командам.\n");
        printf("Нажмите Ctrl+C для выхода.\n");
        while (1) {
            sleep(1);
        }
    }
    
    cleanup();
    return 0;
}
