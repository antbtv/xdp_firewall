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

#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE 2U
#endif
#ifndef XDP_FLAGS_DRV_MODE
#define XDP_FLAGS_DRV_MODE 4U
#endif
#ifndef XDP_FLAGS_UPDATE_IF_NOEXIST
#define XDP_FLAGS_UPDATE_IF_NOEXIST 1U
#endif

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
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t processing_time_ns;
};

static int rules_map_fd = -1;
static int blocked_ips_fd = -1;
static int stats_map_fd = -1;
static int prog_fd = -1;
static int ifindex = -1;

//static void cleanup() {
//    if (ifindex > 0 && prog_fd > 0) {
//        printf("Отключаем XDP программу от интерфейса...\n");
//        bpf_xdp_detach(ifindex, 0, NULL);
//    }
//}

//static void signal_handler(int sig) {
//    (void)sig;
//    cleanup();
//    exit(0);
//}

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

static int delete_rule(uint32_t rule_id) {
    if (bpf_map_delete_elem(rules_map_fd, &rule_id) != 0) {
        printf("Ошибка удаления правила %u: %s\n", rule_id, strerror(errno));
        return -1;
    }
    printf("Правило %u удалено\n", rule_id);
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

static int unblock_ip(const char *ip_str) {
    uint32_t ip = ip_to_int(ip_str);
    if (ip == 0) {
        printf("Ошибка: некорректный IP адрес\n");
        return -1;
    }
    if (bpf_map_delete_elem(blocked_ips_fd, &ip) != 0) {
        printf("Ошибка разблокировки IP %s: %s\n", ip_str, strerror(errno));
        return -1;
    }
    printf("IP %s разблокирован\n", ip_str);
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

// Функция для непрерывного мониторинга производительности
static void performance_monitor(int duration_seconds) {
    printf("=== Мониторинг производительности (%d сек) ===\n", duration_seconds);
    printf("Время\tПакетов/сек\tДроп/сек\tПропуск/сек\tCPU%%\n");
    
    struct stats prev_stat = {0};
    struct stats curr_stat = {0};
    uint32_t key = 0;
    
    for (int i = 0; i < duration_seconds; i++) {
        sleep(1);
        
        if (bpf_map_lookup_elem(stats_map_fd, &key, &curr_stat) == 0) {
            uint64_t pps = curr_stat.packets_processed - prev_stat.packets_processed;
            uint64_t drops = curr_stat.packets_dropped - prev_stat.packets_dropped;
            uint64_t passes = curr_stat.packets_passed - prev_stat.packets_passed;
            
            printf("%d\t%lu\t\t%lu\t\t%lu\t\t-\n", i+1, pps, drops, passes);
            
            prev_stat = curr_stat;
        }
    }
}

// Функция для стресс-теста
static void stress_test_mode() {
    printf("=== Режим стресс-теста ===\n");
    printf("Для генерации нагрузки используйте на другом хосте:\n");
    printf("# TCP нагрузка:\n");
    printf("for i in {1..1000}; do nc -w 1 %s 22 & done\n", "192.168.1.100");
    printf("# UDP нагрузка:\n");
    printf("for i in {1..1000}; do echo 'test' | nc -u -w 1 %s 53 & done\n", "192.168.1.100");
    printf("# ICMP нагрузка:\n");
    printf("ping -f %s\n", "192.168.1.100");
    printf("\nНажмите Enter для начала мониторинга...\n");
    getchar();
    
    performance_monitor(60); // Мониторинг 60 секунд
}

// Функция для экспорта данных в CSV
static void export_performance_data(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        printf("Ошибка создания файла %s\n", filename);
        return;
    }
    
    fprintf(file, "Time,Packets_Total,Packets_Dropped,Packets_Passed,Bytes_Processed,TCP_Count,UDP_Count,ICMP_Count\n");
    
    struct stats stat;
    uint32_t key = 0;
    
    for (int i = 0; i < 60; i++) {
        sleep(1);
        if (bpf_map_lookup_elem(stats_map_fd, &key, &stat) == 0) {
            fprintf(file, "%d,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n", 
                   i, stat.packets_processed, stat.packets_dropped, 
                   stat.packets_passed, stat.bytes_processed,
                   stat.tcp_packets, stat.udp_packets, stat.icmp_packets);
        }
    }
    
    fclose(file);
    printf("Данные экспортированы в %s\n", filename);
}

static void print_usage(const char *prog_name) {
    printf("Использование: %s <интерфейс> [команды]\n\n", prog_name);
    printf("Команды:\n");
    printf("  -r <id> <src_ip> <dst_ip> <src_port> <dst_port> <protocol> <action>\n");
    printf("     Добавить правило (используйте 0 для 'любой')\n");
    printf("     protocol: 0=любой, 1=ICMP, 6=TCP, 17=UDP\n");
    printf("     action: 0=DROP, 1=PASS\n");
    printf("  -rdel <id>         Удалить правило по ID\n");
    printf("  -list              Показать все текущие правила\n");
    printf("  -b <ip>            Заблокировать IP адрес\n");
    printf("  -bun <ip>          Разблокировать IP адрес\n");
    printf("  -s                 Показать статистику\n");
    printf("  -d                 Демон режим (мониторинг)\n");
    printf("  --detach           Полностью отключить XDP Firewall от интерфейса\n\n");
    printf("Примеры:\n");
    printf("  %s eth0 -r 1 0 0 0 22 6 0       # Блокировать SSH на порт 22\n", prog_name);
    printf("  %s eth0 -r 2 192.168.1.100 0 0 0 0 1  # Разрешить трафик с IP\n", prog_name);
    printf("  %s eth0 -b 192.168.1.200         # Заблокировать IP\n", prog_name);
    printf("  %s eth0 -bun 192.168.1.200       # Разблокировать IP\n", prog_name);
    printf("  %s eth0 -rdel 1                  # Удалить правило с ID=1\n", prog_name);
    printf("  %s eth0 -list                    # Показать все правила\n", prog_name);
}

static void list_rules() {
    struct rule rule;
    uint32_t key;
    printf("\n=== Текущие правила ===\n");
    for (key = 0; key < MAX_RULES; key++) {
        if (bpf_map_lookup_elem(rules_map_fd, &key, &rule) == 0 && rule.enabled) {
            struct in_addr src_ip = { .s_addr = htonl(rule.src_ip) };
            struct in_addr dst_ip = { .s_addr = htonl(rule.dst_ip) };

            printf("ID: %u | SRC: %s:%u | DST: %s:%u | PROTO: %u | ACTION: %s\n",
                   key,
                   rule.src_ip ? inet_ntoa(src_ip) : "ANY",
                   rule.src_port,
                   rule.dst_ip ? inet_ntoa(dst_ip) : "ANY",
                   rule.dst_port,
                   rule.protocol,
                   rule.action == 0 ? "DROP" : "PASS");
        }
    }
    printf("=======================\n\n");
}

static void detach_firewall(const char *interface) {
    int idx = if_nametoindex(interface);
    if (idx == 0) {
        printf("Ошибка: интерфейс %s не найден\n", interface);
        return;
    }

    if (bpf_xdp_detach(idx, 0, NULL) != 0) {
        printf("Ошибка отключения XDP от %s: %s\n", interface, strerror(errno));
    } else {
        printf("XDP Firewall успешно отключён от интерфейса %s\n", interface);
    }
}


int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int err;
    
    int test_mode = 0;
    printf(">>> xdp_firewall_user started\n");
    fflush(stdout);

    if (argc >= 3 && strcmp(argv[2], "--test") == 0) {
        test_mode = 1;
    }

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (argc == 3 && strcmp(argv[2], "--detach") == 0) {
        detach_firewall(argv[1]);
        return 0;
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
    printf(">>> BPF object loaded successfully\n");
    fflush(stdout);
    
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
    //signal(SIGINT, signal_handler);
    //signal(SIGTERM, signal_handler);
    
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
        } else if (strcmp(argv[i], "-list") == 0) {
    	    list_rules();
	} else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            // Заблокировать IP
            block_ip(argv[i+1]);
            i++;
        } else if (strcmp(argv[i], "-s") == 0) {
            // Показать статистику
            show_stats();
        } else if (strcmp(argv[i], "-rdel") == 0 && i + 1 < argc) {
    	    uint32_t rule_id = atoi(argv[i+1]);
    	    delete_rule(rule_id);
    	    i++;
	} else if (strcmp(argv[i], "-bun") == 0 && i + 1 < argc) {
    	    unblock_ip(argv[i+1]);
    	    i++;
	}  else if (strcmp(argv[i], "-d") == 0) {
            // Демон режим
            printf("Запущен режим мониторинга. Нажмите Ctrl+C для выхода.\n");
            while (1) {
                sleep(5);
                show_stats();
            }
        } else if (strcmp(argv[i], "-perf") == 0) {
    	    // Тест производительности
   	    performance_monitor(30);
	} else if (strcmp(argv[i], "-stress") == 0) {
    	    // Стресс-тест
    	    stress_test_mode();
	} else if (strcmp(argv[i], "-export") == 0 && i + 1 < argc) {
    	    // Экспорт данных
    	    export_performance_data(argv[i+1]);
    	    i++;
	}
    }
    
    if (argc == 2 || test_mode) {
        if (test_mode) {
            printf(">>> Тестовый режим: ждём 2 секунды и выходим\n");
            sleep(2);
        } else {
            printf("Firewall активен. Используйте -h для справки по командам.\n");
            printf("Нажмите Ctrl+C для выхода.\n");
            while (1) {
                sleep(1);
            }
        }
    }
    
    //cleanup();
    return 0;
}
