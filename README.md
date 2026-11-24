# Amnezia Network Recovery

Bounded, event-driven recovery for a userspace AmneziaWG tunnel on Ubuntu after Wi-Fi/Ethernet reconnects or resume from sleep.

[Русская инструкция](README.ru.md)

NetworkManager starts a 60-second oneshot window. The helper checks the current VPN endpoint route, TCP connectivity bound to the VPN interface, and system DNS separately. A healthy connection is left alone. A deliberately disconnected VPN is not activated.

## Recovery actions

1. Restore a missing IPv4 host route to the current VPN server through the physical gateway.
2. Restore missing VPN DNS settings from a root-only, known-working cache for the same peer and endpoint. TCP through the VPN must work while system DNS fails. New/custom resolver selections and split-DNS domains are preserved.
3. Refresh the **same existing peer endpoint** once per event window after repeated VPN-bound TCP failures, at least 15 seconds of grace, and a handshake at least 180 seconds old. The UAPI request includes only `public_key`, `update_only=true`, and the existing `endpoint`.

The helper does not restart Amnezia or modify private keys, allowed IPs, the host firewall, default routes or Kill Switch. The endpoint refresh uses AmneziaWG's existing UAPI; see [upstream UAPI](https://github.com/amnezia-vpn/amneziawg-go/blob/master/device/uapi.go) and [endpoint source-address caching](https://github.com/amnezia-vpn/amneziawg-go/blob/master/conn/bind_std.go).

This is an experimental workaround for selected failure modes. Successful route checks or a “Connected” UI status alone do not establish that the data path and DNS work.

## Requirements

- Ubuntu with systemd, a running NetworkManager, Python 3.10+, `python3-dbus`, `iproute2` and `getent`.
- One active userspace AmneziaWG peer with an IPv4 endpoint.
- A root-owned socket at `/run/amneziawg/<interface>.sock`, plus a hardware-backed IPv4 Wi-Fi/Ethernet default gateway.

Kernel-only WireGuard/AmneziaWG, IPv6 endpoints, multihop/multiple peers, XRay and OpenVPN are outside this implementation's support.

## Install

```bash
sudo apt update
sudo apt install git python3 python3-dbus iproute2
git clone https://github.com/tupkalov/amnezia-network-recovery.git
cd amnezia-network-recovery
```

Connect AmneziaWG and confirm both internet and DNS work; installation needs a healthy DNS baseline. Preview:

```bash
/usr/bin/python3 -I install.py --interface amn0
```

The default mode makes no changes. Replace `amn0` with the actual VPN interface. To inspect socket names locally, use `sudo ls /run/amneziawg/`.

Fresh installation:

```bash
sudo /usr/bin/python3 -I install.py --install --interface amn0
```

Upgrade a complete existing installation of this helper:

```bash
sudo /usr/bin/python3 -I install.py --install --upgrade --interface amn0
```

Upgrade saves the original three files in `/var/lib/amnezia-route-repair/portable-backup-...`. The installer refuses an incomplete installation and waits for you to retry if a recovery window is already running. Preflight is read-only; installation captures a healthy DNS baseline and does not cycle the VPN.

The installed dispatcher handles `up`, `dhcp4-change` and `reapply` events for physical adapters. No `systemctl enable` is needed. `inactive (dead)` between events is expected.

## Inspect and diagnose

```bash
sudo /usr/bin/python3 -I /usr/local/libexec/amnezia-route-repair.py --check
journalctl -u amnezia-route-repair.service -n 30 --no-pager
```

`--check` is read-only. `vpn_tcp`, `system_dns`, and `vpn_dns_configured` describe separate components. A large `handshake_age_seconds` value by itself does not trigger recovery.

Journal events include `health`, `cached_vpn_dns_restored`, `existing_endpoint_refreshed`, and `summary`. The summary counts route/DNS repairs, endpoint refreshes and transient errors. Raw UAPI replies and secret keys are never logged.

Save a DNS baseline manually while the connection is healthy:

```bash
sudo /usr/bin/python3 -I /usr/local/libexec/amnezia-route-repair.py --capture-dns
```

The root-only cache lives in `/run/amnezia-route-repair/dns.json` and is reset by reboot. It is refreshed during network-event windows with healthy VPN/DNS. If the VPN is connected after the last event window has ended, run `--capture-dns` to initialize the cache. Without a matching cache the helper does not guess DNS servers.

`--repair` without additional recovery flags retains the original single-host-route repair. The service enables the bounded endpoint/DNS actions explicitly.

## Remove

```bash
sudo rm /etc/NetworkManager/dispatcher.d/90-amnezia-route-repair
sudo systemctl stop amnezia-route-repair.service
sudo rm /etc/systemd/system/amnezia-route-repair.service
sudo rm /usr/local/libexec/amnezia-route-repair.py
sudo systemctl daemon-reload
```

These commands remove the automation without disconnecting Amnezia or resetting current routes/DNS. Keep any upgrade backup you may need.

## Tests and limitations

```bash
/usr/bin/python3 -I tests.py
```

Tests run without root and use synthetic peer data and mocks. They cover stale-handshake gates, disconnected/healthy tunnels, identity changes, exact UAPI payloads, DNS-cache validation and preservation of custom settings. CI adds installer rendering and shell syntax checks; it does not exercise a live VPN or emulate suspend/resume.

A DNS failure and a stalled data path can have different causes. These actions cover only the conditions above; inspect the component-level journal output if connectivity remains broken. Do not attach raw UAPI dumps, VPN profiles, private keys or full personal logs to public issues.

## Related

[Claude VPN Guard](https://github.com/tupkalov/claude-vpn-guard) applies a launcher-scoped VPN firewall to Claude. Both projects install independently.

## License

MIT. Independent utility, unaffiliated with the Amnezia project.
