# XDP Firewall
## Требования
- ARM архитектура (протестировано на Raspberry Pi)
- Linux kernel 4.18+ с поддержкой XDP
- Debian-based операционная система (желательна Ubuntu Server)
## Установка
### Установка зависимостей
bash
# Обновление системы
sudo apt update
# Установка компилятора и инструментов разработки
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r)
sudo apt install -y build-essential pkg-config libelf-dev

### Сборка проекта
bash
# Клонирование репозитория
git clone https://github.com/antbtv/xdp_firewall.git
cd xdp_firewall
# Сборка
make clean all

## Использование
### Основной синтаксис
bash
sudo ./xdp_firewall_user <интерфейс> [команды]

### Команды
#### Управление правилами
Добавить правило:
bash
sudo ./xdp_firewall_user <интерфейс> -r <id> <src_ip> <dst_ip> <src_port> <dst_port> <protocol> <action>

Параметры:
- id - уникальный идентификатор правила
- src_ip - IP адрес источника (0 для любого)
- dst_ip - IP адрес назначения (0 для любого)
- src_port - порт источника (0 для любого)
- dst_port - порт назначения (0 для любого)
- protocol - протокол: 0=любой, 1=ICMP, 6=TCP, 17=UDP
- action - действие: 0=DROP (блокировать), 1=PASS (разрешить)
Удалить правило:
bash
sudo ./xdp_firewall_user <интерфейс> -rdel <id>

Показать все правила:
bash
sudo ./xdp_firewall_user <интерфейс> -list

#### Быстрая блокировка IP
Заблокировать IP адрес:
bash
sudo ./xdp_firewall_user <интерфейс> -b <ip>

Разблокировать IP адрес:
bash
sudo ./xdp_firewall_user <интерфейс> -bun <ip>

#### Мониторинг
Показать статистику:
bash
sudo ./xdp_firewall_user <интерфейс> -s

Режим демона (мониторинг в реальном времени):
bash
sudo ./xdp_firewall_user <интерфейс> -d

#### Управление службой
Полностью отключить XDP Firewall:
bash
sudo ./xdp_firewall_user <интерфейс> --detach

## Примеры использования
### Базовая защита
bash
# Блокировать SSH доступ на порт 22
sudo ./xdp_firewall_user eth0 -r 1 0 0 0 22 6 0
# Разрешить трафик с определенного IP
sudo ./xdp_firewall_user eth0 -r 2 192.168.1.100 0 0 0 0 1
# Заблокировать подозрительный IP
sudo ./xdp_firewall_user eth0 -b 192.168.1.200

### Защита веб-сервера
bash
# Разрешить HTTP трафик
sudo ./xdp_firewall_user eth0 -r 10 0 0 0 80 6 1
# Разрешить HTTPS трафик
sudo ./xdp_firewall_user eth0 -r 11 0 0 0 443 6 1
# Блокировать все остальные входящие соединения
sudo ./xdp_firewall_user eth0 -r 99 0 0 0 0 0 0

### Управление правилами
bash
# Просмотр текущих правил
sudo ./xdp_firewall_user eth0 -list
# Удаление правила
sudo ./xdp_firewall_user eth0 -rdel 1
# Разблокировка IP
sudo ./xdp_firewall_user eth0 -bun 192.168.1.200

### Мониторинг
bash
# Просмотр статистики
sudo ./xdp_firewall_user eth0 -s
# Непрерывный мониторинг
sudo ./xdp_firewall_user eth0 -d

## Сетевые интерфейсы
- eth0 - проводное соединение
- wlan0 - Wi-Fi соединение
Для просмотра доступных интерфейсов:
bash
ip link show

---
Автор: antbtv  
Репозиторий: https://github.com/antbtv/xdp_firewall  
Вопросы: antonbut48@gmail.com
