#!/usr/bin/python3 -I
"""Bounded AmneziaWG recovery after physical network events.

Default/--check is read-only. --repair retains the original endpoint host-route
repair. Optional recovery flags additionally restore missing cached VPN DNS or
refresh the SAME existing peer endpoint after stale-handshake/data failures.
Never activates a VPN, restarts Amnezia, changes keys, firewall or default routes.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time

SOCKET = Path('/run/amneziawg/amn0.sock')
INTERFACE = Path('/sys/class/net/amn0')
STATE = Path('/run/amnezia-route-repair/dns.json')
IP = '/usr/sbin/ip'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}
PUBLIC_PROBES = [('1.1.1.1', 443), ('9.9.9.9', 53)]
STALE_HANDSHAKE_SECONDS = 180
REFRESH_GRACE_SECONDS = 15

def ip_json(*args):
    return json.loads(subprocess.run([IP, '-j', '-4', *args], capture_output=True, text=True,
                                     check=True, timeout=4, env=ENV).stdout)

def socket_identity():
    info = SOCKET.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
        raise RuntimeError('Tunnel socket is not root-owned')
    if not INTERFACE.exists():
        raise RuntimeError('Tunnel interface is absent')
    return info.st_ino, INTERFACE.stat().st_ino

def parse_get(response):
    # Deliberately retain no private/preshared keys or raw response text.
    fields = {'public_key': [], 'endpoint': [], 'last_handshake_time_sec': []}
    status = None
    consumed = 0
    for line in response:
        consumed += len(line)
        if consumed > 1024 * 1024 or len(line) > 8192:
            raise RuntimeError('Tunnel response exceeds limit')
        if line == '\n':
            break
        key, separator, value = line.strip().partition('=')
        if key in fields:
            fields[key].append(value)
        elif key == 'errno':
            status = int(value)
    else:
        raise RuntimeError('Incomplete tunnel response')
    if status != 0 or any(len(values) != 1 for values in fields.values()):
        raise RuntimeError('Expected a successful GET with exactly one peer')
    public = fields['public_key'][0]
    if not re.fullmatch(r'[0-9a-fA-F]{64}', public):
        raise RuntimeError('Invalid peer public key')
    host, separator, raw_port = fields['endpoint'][0].rpartition(':')
    address = ipaddress.ip_address(host)
    port = int(raw_port)
    if not separator or address.version != 4 or not 1 <= port <= 65535 or address.is_unspecified or address.is_loopback or address.is_multicast:
        raise RuntimeError('Expected an IPv4 VPN endpoint')
    handshake = int(fields['last_handshake_time_sec'][0])
    if handshake < 0:
        raise RuntimeError('Invalid handshake timestamp')
    endpoint = f'{address}:{port}'
    return {'public_key': public.lower(), 'endpoint': endpoint, 'endpoint_ip': str(address),
            'handshake_age_seconds': max(0, int(time.time()) - handshake) if handshake else None,
            'fingerprint': hashlib.sha256((public.lower() + ':' + endpoint).encode()).hexdigest()}

def tunnel_snapshot():
    identity = socket_identity()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(str(SOCKET))
        connection.sendall(b'get=1\n\n')
        with connection.makefile('r', encoding='ascii') as response:
            result = parse_get(response)
    if socket_identity() != identity:
        raise RuntimeError('Tunnel changed during GET')
    result['identity'] = identity
    return result

def physical_gateway():
    candidates = []
    for route in ip_json('route', 'show', 'default'):
        device, gateway = route.get('dev', ''), route.get('gateway')
        if not device or '/' in device or not gateway:
            continue
        net = Path('/sys/class/net') / device
        if not (net / 'device').exists() or (net / 'operstate').read_text().strip() != 'up':
            continue
        if ipaddress.ip_address(gateway).version != 4:
            continue
        candidates.append((int(route.get('metric', 0)), device, str(gateway)))
    if not candidates:
        raise RuntimeError('Physical IPv4 gateway is not ready')
    _, device, gateway = min(candidates)
    return device, gateway

def inspect():
    snapshot = tunnel_snapshot()
    device, gateway = physical_gateway()
    try:
        routes = ip_json('route', 'get', snapshot['endpoint_ip'])
    except subprocess.CalledProcessError:
        routes = []
    current = routes[0] if routes else {}
    report = {'endpoint': snapshot['endpoint_ip'], 'physical_interface': device, 'gateway': gateway,
              'route_needs_repair': current.get('dev') != device or current.get('gateway') != gateway,
              'handshake_age_seconds': snapshot['handshake_age_seconds']}
    return report, snapshot

def revalidate(report, snapshot):
    current = tunnel_snapshot()
    if current['identity'] != snapshot['identity'] or current['fingerprint'] != snapshot['fingerprint']:
        raise RuntimeError('Tunnel or peer changed; recovery cancelled')
    if physical_gateway() != (report['physical_interface'], report['gateway']):
        raise RuntimeError('Physical gateway changed; recovery cancelled')
    return current

def repair(report, snapshot):
    if not report['route_needs_repair']:
        return 'already_correct'
    revalidate(report, snapshot)
    subprocess.run([IP, '-4', 'route', 'replace', report['endpoint'] + '/32',
                    'via', report['gateway'], 'dev', report['physical_interface']],
                   check=True, capture_output=True, text=True, timeout=4, env=ENV)
    return 'host_route_restored'

def vpn_tcp():
    # Binding is mandatory: no fallback to a physical interface is permitted.
    for host, port in PUBLIC_PROBES:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.settimeout(1.5)
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, INTERFACE.name.encode() + b'\0')
                connection.connect((host, port))
                return True
        except OSError:
            continue
    return False

def system_dns():
    try:
        result = subprocess.run(['/usr/bin/getent', 'ahostsv4', 'example.com'],
                                capture_output=True, timeout=3, env=ENV)
        return result.returncode == 0 and bool(result.stdout)
    except subprocess.SubprocessError:
        return False

def dns_link():
    import dbus
    bus = dbus.SystemBus()
    try:
        manager = dbus.Interface(bus.get_object('org.freedesktop.resolve1', '/org/freedesktop/resolve1'), 'org.freedesktop.resolve1.Manager')
        index = socket.if_nametoindex(INTERFACE.name)
        path = manager.GetLink(index, timeout=3)
        properties = dbus.Interface(bus.get_object('org.freedesktop.resolve1', path), 'org.freedesktop.DBus.Properties')
        data = properties.GetAll('org.freedesktop.resolve1.Link', timeout=3)
        servers = [socket.inet_ntop(int(family), bytes(raw)) for family, raw in data['DNS']]
        domains = [[str(name), bool(routing)] for name, routing in data['Domains']]
        return {'servers': servers, 'domains': domains, 'default_route': bool(data['DefaultRoute'])}
    finally:
        bus.close()

def validate_dns(data):
    if not isinstance(data, dict) or not isinstance(data.get('servers'), list) or not data['servers'] or len(data['servers']) > 8:
        return False
    try:
        for server in data['servers']:
            ipaddress.ip_address(server)
    except (ValueError, TypeError):
        return False
    domains = data.get('domains')
    return (isinstance(domains, list) and len(domains) <= 32 and
            all(isinstance(d, list) and len(d) == 2 and isinstance(d[0], str) and
                re.fullmatch(r'[A-Za-z0-9_.-]{1,253}', d[0]) and type(d[1]) is bool for d in domains)
            and type(data.get('default_route')) is bool)

def load_dns(snapshot):
    try:
        info = STATE.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_size > 16384:
            return None
        data = json.loads(STATE.read_text())
        if data.get('fingerprint') == snapshot['fingerprint'] and validate_dns(data.get('dns')):
            return data['dns']
    except (OSError, ValueError, TypeError):
        pass
    return None

def save_dns(snapshot, data):
    if not validate_dns(data):
        return False
    STATE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.dns-', dir=STATE.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump({'fingerprint': snapshot['fingerprint'], 'dns': data}, stream)
        os.chmod(name, 0o600)
        os.replace(name, STATE)
    finally:
        Path(name).unlink(missing_ok=True)
    return True

def dns_missing(current, cached):
    if not cached or not validate_dns(cached):
        return False
    if current['servers'] and current['servers'] != cached['servers']:
        return False  # Do not replace a new/custom resolver selection.
    if current['domains'] and current['domains'] != cached['domains']:
        return False  # New split-DNS routing policy is also an intentional choice.
    return not current['servers'] or bool(cached['domains']) and not current['domains']

def restore_dns(report, snapshot, cached):
    if not validate_dns(cached):
        raise RuntimeError('No valid cached VPN DNS')
    revalidate(report, snapshot)
    if not dns_missing(dns_link(), cached):
        raise RuntimeError('DNS selection changed; restoration cancelled')
    import dbus
    bus = None
    try:
        bus = dbus.SystemBus()
        manager = dbus.Interface(bus.get_object('org.freedesktop.resolve1', '/org/freedesktop/resolve1'), 'org.freedesktop.resolve1.Manager')
        index = socket.if_nametoindex(INTERFACE.name)
        servers = []
        for address in cached['servers']:
            parsed = ipaddress.ip_address(address)
            servers.append((dbus.Int32(socket.AF_INET if parsed.version == 4 else socket.AF_INET6),
                            dbus.Array(parsed.packed, signature='y')))
        manager.SetLinkDNS(index, dbus.Array(servers, signature='(iay)'), timeout=3)
        manager.SetLinkDomains(index, dbus.Array([(dbus.String(d), dbus.Boolean(r)) for d, r in cached['domains']], signature='(sb)'), timeout=3)
        manager.SetLinkDefaultRoute(index, dbus.Boolean(cached['default_route']), timeout=3)
    except Exception:
        raise RuntimeError('DNS restoration unavailable') from None
    finally:
        if bus:
            bus.close()

def refresh_payload(snapshot):
    public, endpoint = snapshot['public_key'], snapshot['endpoint']
    if not re.fullmatch(r'[0-9a-f]{64}', public) or not re.fullmatch(r'[0-9.]+:[0-9]+', endpoint):
        raise RuntimeError('Invalid refresh fields')
    host, raw_port = endpoint.rsplit(':', 1)
    if ipaddress.ip_address(host).version != 4 or not 1 <= int(raw_port) <= 65535:
        raise RuntimeError('Invalid refresh endpoint')
    return f'set=1\npublic_key={public}\nupdate_only=true\nendpoint={endpoint}\n\n'.encode('ascii')

def refresh_endpoint(report, snapshot):
    current = revalidate(report, snapshot)
    payload = refresh_payload(current)
    # update_only forbids re-creating a peer removed by a concurrent disconnect.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(str(SOCKET))
        if socket_identity() != snapshot['identity']:
            raise RuntimeError('Tunnel replaced before refresh')
        connection.sendall(payload)
        with connection.makefile('r', encoding='ascii') as response:
            size, status = 0, None
            for line in response:
                size += len(line)
                if size > 8192:
                    raise RuntimeError('Unexpected SET response')
                if line == '\n':
                    break
                key, separator, value = line.strip().partition('=')
                if key == 'errno':
                    status = int(value)
            else:
                raise RuntimeError('Incomplete SET response')
            if status != 0:
                raise RuntimeError('Endpoint refresh was rejected')

def should_refresh(age, failures, elapsed, already_refreshed):
    return (not already_refreshed and age is not None and age >= STALE_HANDSHAKE_SECONDS
            and failures >= 2 and elapsed >= REFRESH_GRACE_SECONDS)

def log(event, **values):
    print(json.dumps({'event': event, **values}, sort_keys=True), flush=True)

def watch(seconds, allow_refresh, allow_dns):
    start = time.monotonic()
    checks = routes = dns_repairs = refreshes = failures = errors = 0
    refresh_attempted = dns_attempted = False
    last_probe, previous = -100.0, None
    while time.monotonic() - start < seconds:
        try:
            report, snapshot = inspect()
            checks += 1
            routes += repair(report, snapshot) == 'host_route_restored'
            now = time.monotonic()
            if now - last_probe >= 4:
                last_probe = now
                data_ok, dns_ok = vpn_tcp(), system_dns()
                try:
                    configured = dns_link()
                except Exception:
                    configured = None
                if data_ok and dns_ok and configured:
                    save_dns(snapshot, configured)
                failures = 0 if data_ok else failures + 1
                status = (data_ok, dns_ok, bool(configured and configured['servers']))
                if status != previous:
                    log('health', vpn_tcp=data_ok, system_dns=dns_ok, vpn_dns_configured=status[2], handshake_age_seconds=report['handshake_age_seconds'])
                    previous = status
                if allow_dns and data_ok and not dns_ok and configured is not None and not dns_attempted:
                    cached = load_dns(snapshot)
                    if dns_missing(configured, cached):
                        dns_attempted = True
                        restore_dns(report, snapshot, cached)
                        dns_repairs += 1
                        log('cached_vpn_dns_restored')
                if allow_refresh and not data_ok and should_refresh(report['handshake_age_seconds'], failures, time.monotonic() - start, refresh_attempted):
                    refresh_attempted = True
                    refresh_endpoint(report, snapshot)
                    refreshes += 1
                    log('existing_endpoint_refreshed')
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            errors += 1
            failures = 0
            # Do not log exception text: parsing errors could contain raw fields.
            if errors == 1:
                log('temporarily_unavailable', error_type=type(error).__name__)
        time.sleep(1)
    log('summary', checks=checks, host_routes_restored=routes, dns_restored=dns_repairs, endpoint_refreshes=refreshes, transient_errors=errors)
    return 0

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--repair', action='store_true')
    mode.add_argument('--capture-dns', action='store_true', help='save a healthy DNS baseline without changing network settings')
    parser.add_argument('--watch-seconds', type=int, default=0)
    parser.add_argument('--refresh-endpoint', action='store_true')
    parser.add_argument('--restore-dns', action='store_true')
    args = parser.parse_args()
    if not 0 <= args.watch_seconds <= 60 or (args.watch_seconds and not args.repair):
        parser.error('--watch-seconds requires --repair and 1..60')
    if (args.refresh_endpoint or args.restore_dns) and not (args.repair and args.watch_seconds):
        parser.error('Recovery flags require --repair --watch-seconds')
    if os.geteuid() != 0:
        parser.exit(1, 'Root is required to read the tunnel socket.\n')
    if args.watch_seconds:
        return watch(args.watch_seconds, args.refresh_endpoint, args.restore_dns)
    try:
        report, snapshot = inspect()
        if args.repair:
            report['result'] = repair(report, snapshot)
        report['vpn_tcp'] = vpn_tcp()
        report['system_dns'] = system_dns()
        try:
            current = dns_link()
            report['vpn_dns_configured'] = bool(current['servers'])
        except Exception:
            current = None
            report['vpn_dns_configured'] = None
        if args.capture_dns:
            if not report['vpn_tcp'] or not report['system_dns'] or not current or not save_dns(snapshot, current):
                raise RuntimeError('Cannot save a healthy VPN DNS baseline')
            report['dns_baseline_saved'] = True
        print(json.dumps(report, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        log('no_action', error_type=type(error).__name__)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
