#!/usr/bin/python3 -I
"""Install the existing event-driven route workaround on another Ubuntu."""
import argparse
import ast
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
TARGETS = {
    'amnezia-route-repair.py': ('/usr/local/libexec/amnezia-route-repair.py', 0o755),
    'amnezia-route-repair.service': ('/etc/systemd/system/amnezia-route-repair.service', 0o644),
    '90-amnezia-route-repair': ('/etc/NetworkManager/dispatcher.d/90-amnezia-route-repair', 0o755),
}

def render(interface):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', interface) or interface in ('.', '..', 'lo'):
        raise ValueError('Invalid VPN interface name')
    result = {name: (HERE / name).read_text() for name in TARGETS}
    result['amnezia-route-repair.py'] = result['amnezia-route-repair.py'].replace(
        "Path('/run/amneziawg/amn0.sock')", f"Path('/run/amneziawg/{interface}.sock')").replace(
        "Path('/sys/class/net/amn0')", f"Path('/sys/class/net/{interface}')")
    ast.parse(result['amnezia-route-repair.py'], feature_version=(3, 10))
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', default='amn0')
    parser.add_argument('--install', action='store_true', help='copy files; default is preview only')
    parser.add_argument('--upgrade', action='store_true', help='explicitly back up and replace existing complete installation')
    args = parser.parse_args()
    data = render(args.interface)
    print(json.dumps({'interface': args.interface,
                      'requires_socket': f'/run/amneziawg/{args.interface}.sock',
                      'targets': {name: target for name, (target, mode) in TARGETS.items()},
                      'mode': 'install' if args.install else 'preview'}, indent=2), flush=True)
    if not args.install:
        return
    if os.geteuid() != 0:
        raise ValueError('Run --install with sudo')
    if not Path('/etc/NetworkManager/dispatcher.d').is_dir():
        raise ValueError('NetworkManager dispatcher directory not found')
    if not Path('/usr/sbin/ip').is_file():
        raise ValueError('Install iproute2 first')
    check = subprocess.run(['/usr/bin/systemctl', 'is-active', 'NetworkManager.service'], capture_output=True, text=True)
    if check.returncode:
        raise ValueError('This workaround requires an active NetworkManager service')
    # Preflight is read-only: verifies the target uses the supported userspace
    # socket and a physical IPv4 gateway. No route repair runs during installation.
    with tempfile.TemporaryDirectory(prefix='amnezia-route-check-') as directory:
        path = Path(directory) / 'check.py'
        path.write_text(data['amnezia-route-repair.py'])
        result = subprocess.run(['/usr/bin/python3', '-I', str(path), '--check'], capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise ValueError('Connect a supported AmneziaWG tunnel first. ' + result.stderr.strip())
        health=json.loads(result.stdout)
        if not health['vpn_tcp'] or not health['system_dns'] or not health['vpn_dns_configured'] or health['route_needs_repair']:
            raise ValueError('Reconnect Amnezia first; a healthy baseline is required before installation')
        print('READ_ONLY_CHECK_PASS', flush=True)
    present=[Path(target).exists() or Path(target).is_symlink() for target, mode in TARGETS.values()]
    if any(present) and (not args.upgrade or not all(present)):
        raise ValueError('Existing/incomplete setup found; --upgrade is required for a complete existing installation')
    if args.upgrade and not all(present):
        raise ValueError('--upgrade requires all three existing components')
    active=subprocess.run(['/usr/bin/systemctl','is-active','--quiet','amnezia-route-repair.service'])
    if active.returncode==0:
        raise ValueError('Wait for the current recovery window to finish before installing')
    backup=None
    if args.upgrade:
        backup=Path('/var/lib/amnezia-route-repair')/datetime.datetime.now().strftime('portable-backup-%Y%m%d-%H%M%S')
        backup.mkdir(parents=True,mode=0o700)
        for name,(target,mode) in TARGETS.items():
            if Path(target).is_symlink():raise ValueError('Refusing to replace symlinked recovery components')
            shutil.copy2(target,backup/name)
    state=Path('/run/amnezia-route-repair/dns.json')
    old_state=state.read_bytes() if state.is_file() else None
    installed = []
    try:
        for name, (target, mode) in TARGETS.items():
            path = Path(target)
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix='.route-repair-', dir=path.parent)
            with os.fdopen(fd, 'w') as stream:
                stream.write(data[name])
            os.chmod(temporary, mode)
            os.replace(temporary, path)
            installed.append(path)
        subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True)
        captured=subprocess.run(['/usr/bin/python3','-I',str(Path(TARGETS['amnezia-route-repair.py'][0])),'--capture-dns'],capture_output=True,text=True,check=True,timeout=20)
        if not json.loads(captured.stdout).get('dns_baseline_saved'):
            raise RuntimeError('Healthy DNS baseline was not saved')
    except BaseException:
        subprocess.run(['/usr/bin/systemctl','stop','amnezia-route-repair.service'],check=False)
        for path in reversed(installed):
            path.unlink(missing_ok=True)
        if backup:
            for name,(target,mode) in TARGETS.items():shutil.copy2(backup/name,target)
        if old_state is None:state.unlink(missing_ok=True)
        else:state.write_bytes(old_state);state.chmod(0o600)
        subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=False)
        raise
    print('INSTALLED; DNS_BASELINE_SAVED. NetworkManager will invoke the oneshot on future physical network events. No enable/start required.', flush=True)

if __name__ == '__main__':
    try:
        main()
    except (ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
