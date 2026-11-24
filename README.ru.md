# Amnezia Network Recovery

Автовосстановление отдельных частей подключения AmneziaWG на Ubuntu после сна или смены Wi-Fi/Ethernet. NetworkManager запускает проверку на 60 секунд.

Скрипт проверяет маршрут к серверу, передачу данных через VPN и системный DNS. При необходимости восстанавливает host route, пропавшие настройки DNS из рабочего кэша того же VPN или однократно обновляет прежний endpoint существующего peer после повторных ошибок и устаревшего handshake.

Amnezia не перезапускается, выключенный VPN не включается. Секретные ключи, firewall, default route и Kill Switch не меняются. Здоровое соединение не сбрасывается.

## Установка

Нужны работающий NetworkManager, systemd, Python 3.10+, python3-dbus и iproute2. Поддерживается один userspace AmneziaWG peer с IPv4 endpoint и root-owned сокетом `/run/amneziawg/<интерфейс>.sock`.

```bash
sudo apt update
sudo apt install git python3 python3-dbus iproute2
git clone https://github.com/tupkalov/amnezia-network-recovery.git
cd amnezia-network-recovery
```

Сначала подключите AmneziaWG и проверьте, что интернет и DNS работают. Посмотрите план:

```bash
/usr/bin/python3 -I install.py --interface amn0
```

Замените `amn0`, если интерфейс называется иначе. Просмотр ничего не меняет.

Новая установка:

```bash
sudo /usr/bin/python3 -I install.py --install --interface amn0
```

Если уже установлена предыдущая версия этого механизма:

```bash
sudo /usr/bin/python3 -I install.py --install --upgrade --interface amn0
```

Обновление сохраняет исходные файлы в `/var/lib/amnezia-route-repair/portable-backup-...`. Установщик сначала проверяет совместимость и сохраняет рабочий DNS-кэш. Подключение VPN не переключается.

## Проверка

```bash
sudo /usr/bin/python3 -I /usr/local/libexec/amnezia-route-repair.py --check
journalctl -u amnezia-route-repair.service -n 30 --no-pager
```

`--check` ничего не меняет. `inactive (dead)` между сетевыми событиями нормально: служба одноразовая, `systemctl enable` не нужен. В журнале `health` показывает состояние компонентов, а `summary` — число исправлений и ошибок.

DNS-кэш в `/run` сбрасывается после перезагрузки. Он обновляется во время окна сетевого события при здоровом соединении. Если VPN подключён позже, сохраните базу вручную:

```bash
sudo /usr/bin/python3 -I /usr/local/libexec/amnezia-route-repair.py --capture-dns
```

Кэш привязан к тому же peer/endpoint; новые серверы или DNS-домены не подменяются. Без кэша адреса DNS не угадываются.

Kernel-only WireGuard/AmneziaWG, IPv6 endpoint, multihop, XRay и OpenVPN не поддержаны. Подробности, удаление и тесты — в [основной инструкции](README.md). Проверки без root: `/usr/bin/python3 -I tests.py`.
