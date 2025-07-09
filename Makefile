CC = clang
CFLAGS = -O2 -g -Wall -Wextra

BPF_CFLAGS = -O2 -g -target bpf -I. \
    -Wall -Wno-unused-value -Wno-pointer-sign \
    -Wno-gnu-variable-sized-type-not-at-end \
    -Wno-address-of-packed-member

USER_CFLAGS = $(CFLAGS) -I/usr/include
USER_LDFLAGS = -lbpf -lelf -lz

TARGETS = xdp_firewall_kern.o xdp_firewall_user

.PHONY: all clean install

all: $(TARGETS)

xdp_firewall_kern.o: xdp_firewall_kern.c
	$(CC) $(BPF_CFLAGS) -c $< -o $@

xdp_firewall_user: xdp_firewall_user.c
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

clean:
	rm -f $(TARGETS)

install: all
	sudo cp xdp_firewall_user /usr/local/bin/
	sudo cp xdp_firewall_kern.o /usr/local/lib/
	sudo chmod +x /usr/local/bin/xdp_firewall_user

test-compile: all
	@echo "Компиляция завершена успешно"

test-load: all
	@echo "Тестируем загрузку на loopback интерфейсе..."
	@sudo ./xdp_firewall_user lo --test > /tmp/xdp.log 2>&1 &
	@echo "Тест загрузки завершен"
	@cat /tmp/xdp.log

check-deps:
	@echo "Проверяем зависимости..."
	@which clang > /dev/null || (echo "ОШИБКА: clang не установлен" && exit 1)
	@pkg-config --exists libbpf || (echo "ОШИБКА: libbpf-dev не установлен" && exit 1)
	@ls /usr/include/linux/bpf.h > /dev/null || (echo "ОШИБКА: linux-headers не установлены" && exit 1)
	@echo "Все зависимости установлены"

install-deps:
	sudo apt update
	sudo apt install -y clang llvm libbpf-dev linux-headers-$(shell uname -r) \
		build-essential pkg-config libelf-dev

debug-info:
	@echo "=== Информация о системе ==="
	@echo "Архитектура: $(shell uname -m)"
	@echo "Ядро: $(shell uname -r)"
	@echo "Clang: $(shell clang --version | head -1)"
	@echo "libbpf: $(shell pkg-config --modversion libbpf 2>/dev/null || echo 'не найдено')"
	@echo "BPF в ядре: $(shell grep -c CONFIG_BPF=y /boot/config-$(shell uname -r) 2>/dev/null || echo 'неизвестно')"
