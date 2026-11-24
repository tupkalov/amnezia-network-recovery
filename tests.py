#!/usr/bin/python3 -I
import io
import ast
import json
from pathlib import Path
import runpy
import socket
import stat
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch

M = runpy.run_path(str(Path(__file__).with_name('amnezia-route-repair.py')))
G = M['watch'].__globals__
PUBLIC = 'a' * 64
GOOD_DNS = {'servers': ['1.1.1.1', '1.0.0.1'], 'domains': [['.', True]], 'default_route': True}
EMPTY_DNS = {'servers': [], 'domains': [], 'default_route': False}

def response(**changes):
    fields = {'private_key': 'DO_NOT_KEEP_PRIVATE', 'public_key': PUBLIC,
              'preshared_key': 'DO_NOT_KEEP_PSK', 'endpoint': '198.51.100.9:51820',
              'last_handshake_time_sec': '100', 'errno': '0'}
    fields.update(changes)
    return io.StringIO(''.join(k + '=' + v + '\n' for k, v in fields.items()) + '\n')

def snapshot():
    return {'public_key': PUBLIC, 'endpoint': '198.51.100.9:51820',
            'endpoint_ip': '198.51.100.9', 'handshake_age_seconds': 1000,
            'fingerprint': 'peer-fingerprint', 'identity': (10, 20)}

REPORT = {'endpoint': '198.51.100.9', 'physical_interface': 'wlan0', 'gateway': '192.168.50.1',
          'route_needs_repair': False, 'handshake_age_seconds': 1000}

class RecoveryTests(unittest.TestCase):
    def test_get_discards_secret_fields(self):
        parsed = M['parse_get'](response())
        self.assertNotIn('DO_NOT_KEEP', repr(parsed))
        self.assertEqual(parsed['endpoint'], '198.51.100.9:51820')

    def test_get_rejects_multipeer(self):
        text = response().getvalue().replace('errno=0', 'public_key=' + 'b'*64 + '\nendpoint=198.51.100.10:51820\nerrno=0')
        with self.assertRaises(RuntimeError):
            M['parse_get'](io.StringIO(text))

    def test_get_rejects_invalid_or_missing_fields(self):
        for changes in [{'errno': '1'}, {'public_key': 'not-a-key'}, {'endpoint': '127.0.0.1:80'}, {'endpoint': '[2001:db8::1]:80'}]:
            with self.subTest(changes=changes), self.assertRaises((RuntimeError, ValueError)):
                M['parse_get'](response(**changes))
        with self.assertRaises(RuntimeError):
            M['parse_get'](io.StringIO('errno=0\n'))

    def test_refresh_payload_is_only_existing_peer_same_endpoint(self):
        payload = M['refresh_payload'](snapshot()).decode()
        self.assertEqual(payload, 'set=1\npublic_key=' + PUBLIC + '\nupdate_only=true\nendpoint=198.51.100.9:51820\n\n')
        for forbidden in ['private_key', 'preshared_key', 'replace_peers', 'allowed_ip', 'remove=', 'listen_port']:
            self.assertNotIn(forbidden, payload)

    def test_payload_rejects_injection(self):
        for field, value in [('public_key', PUBLIC+'\nremove=true'), ('endpoint', '198.51.100.9:80\nprivate_key=x'), ('endpoint', '198.51.100.9:999999')]:
            data = snapshot(); data[field] = value
            with self.assertRaises((RuntimeError, ValueError)):
                M['refresh_payload'](data)

    def test_refresh_sends_only_validated_same_endpoint(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.makefile.return_value = io.StringIO('errno=0\n\n')
        with patch.dict(G, revalidate=lambda *a:snapshot(), socket_identity=lambda:(10,20)), patch('socket.socket',return_value=connection):
            M['refresh_endpoint'](REPORT,snapshot())
        connection.sendall.assert_called_once_with(M['refresh_payload'](snapshot()))

    def test_refresh_aborts_when_socket_replaced(self):
        connection = MagicMock();connection.__enter__.return_value = connection
        with patch.dict(G,revalidate=lambda *a:snapshot(),socket_identity=lambda:(99,20)), patch('socket.socket',return_value=connection), self.assertRaises(RuntimeError):
            M['refresh_endpoint'](REPORT,snapshot())
        connection.sendall.assert_not_called()

    def test_dns_restore_uses_exact_cached_link_settings(self):
        import dbus
        bus,manager = MagicMock(),MagicMock()
        with patch.dict(G,revalidate=lambda *a:snapshot(),dns_link=lambda:EMPTY_DNS), patch('dbus.SystemBus',return_value=bus), patch('dbus.Interface',return_value=manager), patch('socket.if_nametoindex',return_value=8):
            M['restore_dns'](REPORT,snapshot(),GOOD_DNS)
        args=manager.SetLinkDNS.call_args.args
        self.assertEqual(args[0],8)
        self.assertEqual([bytes(raw) for family,raw in args[1]], [socket.inet_pton(socket.AF_INET,x) for x in GOOD_DNS['servers']])
        self.assertEqual(list(manager.SetLinkDomains.call_args.args[1][0]),['.',True])
        self.assertTrue(manager.SetLinkDefaultRoute.call_args.args[1])

    def test_dns_restore_cancels_new_custom_selection(self):
        changed={**GOOD_DNS,'servers':['10.1.2.3']}
        with patch.dict(G,revalidate=lambda *a:snapshot(),dns_link=lambda:changed), self.assertRaises(RuntimeError):
            M['restore_dns'](REPORT,snapshot(),GOOD_DNS)

    def test_refresh_requires_all_gates(self):
        self.assertTrue(M['should_refresh'](1000, 2, 16, False))
        for args in [(None, 2, 16, False), (5, 2, 16, False), (1000, 1, 16, False), (1000, 2, 5, False), (1000, 2, 16, True)]:
            self.assertFalse(M['should_refresh'](*args))

    def test_revalidate_cancels_peer_and_network_changes(self):
        changed = snapshot(); changed['identity'] = (11, 20)
        with patch.dict(G, tunnel_snapshot=lambda:changed), self.assertRaises(RuntimeError):
            M['revalidate'](REPORT, snapshot())
        with patch.dict(G, tunnel_snapshot=snapshot, physical_gateway=lambda:('wlan0','192.168.99.1')), self.assertRaises(RuntimeError):
            M['revalidate'](REPORT, snapshot())

    def test_route_repair_only_ipv4_host_route(self):
        report = {**REPORT, 'route_needs_repair': True}
        with patch.dict(G, revalidate=lambda *a:snapshot()), patch('subprocess.run') as run:
            self.assertEqual(M['repair'](report, snapshot()), 'host_route_restored')
            self.assertEqual(run.call_args.args[0], ['/usr/sbin/ip','-4','route','replace','198.51.100.9/32','via','192.168.50.1','dev','wlan0'])
        with patch('subprocess.run') as run:
            self.assertEqual(M['repair'](REPORT, snapshot()), 'already_correct')
            run.assert_not_called()

    def test_dns_no_fallback_and_no_custom_overwrite(self):
        self.assertTrue(M['dns_missing'](EMPTY_DNS, GOOD_DNS))
        self.assertFalse(M['dns_missing'](EMPTY_DNS, None))
        self.assertFalse(M['dns_missing'](GOOD_DNS, GOOD_DNS))
        custom = {**GOOD_DNS, 'servers': ['10.1.2.3']}
        self.assertFalse(M['dns_missing'](custom, GOOD_DNS))
        custom_domains = {**GOOD_DNS, 'domains': [['office.example', True]], 'default_route': False}
        self.assertFalse(M['dns_missing'](custom_domains, GOOD_DNS))
        different_default = {**GOOD_DNS, 'default_route': False}
        self.assertFalse(M['dns_missing'](different_default, GOOD_DNS))

    def test_dns_validation(self):
        self.assertTrue(M['validate_dns'](GOOD_DNS))
        self.assertFalse(M['validate_dns']({**GOOD_DNS, 'servers': ['1.1.1.1\ninject']}))
        self.assertFalse(M['validate_dns']({**GOOD_DNS, 'domains': [['.\ninject',True]]}))

    def test_cache_is_bound_to_peer(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)/'dns.json'
            state.write_text(json.dumps({'fingerprint':'peer-fingerprint','dns':GOOD_DNS}))
            state.chmod(0o600)
            real = Path.lstat
            def pretend_root(p):
                result = real(p)
                return types.SimpleNamespace(st_mode=result.st_mode,st_uid=0,st_size=result.st_size)
            with patch.dict(G, STATE=state), patch.object(Path,'lstat',pretend_root):
                self.assertEqual(M['load_dns'](snapshot()), GOOD_DNS)
                other = snapshot(); other['fingerprint'] = 'different-peer'
                self.assertIsNone(M['load_dns'](other))

    def test_data_probe_always_binds_to_vpn(self):
        mock = MagicMock()
        mock.__enter__.return_value = mock
        mock.connect.side_effect = OSError('down')
        with patch('socket.socket', return_value=mock):
            self.assertFalse(M['vpn_tcp']())
            self.assertEqual(mock.setsockopt.call_count, len(M['PUBLIC_PROBES']))
            for call in mock.setsockopt.call_args_list:
                self.assertEqual(call.args, (socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'amn0\0'))

    def run_watch(self, data_ok, dns_ok, configured, fail_refresh=False, healthy_age=1000):
        tick = [0.0]
        def sleep(seconds): tick[0] += seconds
        refreshed = MagicMock(side_effect=RuntimeError('failed') if fail_refresh else None)
        restored = MagicMock()
        report = {**REPORT,'handshake_age_seconds':healthy_age}
        patches = {'inspect':lambda:(report,snapshot()),'repair':lambda *a:'already_correct',
                   'vpn_tcp':lambda:data_ok,'system_dns':lambda:dns_ok,'dns_link':lambda:configured,
                   'load_dns':lambda *a:GOOD_DNS,'save_dns':MagicMock(),'refresh_endpoint':refreshed,
                   'restore_dns':restored,'log':MagicMock()}
        with patch.dict(G, **patches), patch('time.monotonic',side_effect=lambda:tick[0]), patch('time.sleep',side_effect=sleep):
            M['watch'](35,True,True)
        return refreshed, restored, patches

    def test_healthy_tunnel_never_reset(self):
        refreshed,restored,p = self.run_watch(True,True,GOOD_DNS)
        refreshed.assert_not_called();restored.assert_not_called()
        self.assertGreater(p['save_dns'].call_count,0)

    def test_stale_failed_tunnel_refreshed_once(self):
        refreshed,restored,p = self.run_watch(False,False,GOOD_DNS)
        self.assertEqual(refreshed.call_count,1)
        restored.assert_not_called()

    def test_failed_refresh_not_repeated(self):
        refreshed,restored,p = self.run_watch(False,False,GOOD_DNS,fail_refresh=True)
        self.assertEqual(refreshed.call_count,1)

    def test_missing_dns_restored_once_without_tunnel_refresh(self):
        refreshed,restored,p = self.run_watch(True,False,EMPTY_DNS)
        refreshed.assert_not_called();self.assertEqual(restored.call_count,1)

    def test_fresh_handshake_never_reset(self):
        refreshed,restored,p = self.run_watch(False,False,GOOD_DNS,healthy_age=5)
        refreshed.assert_not_called()

    def test_disconnected_tunnel_no_actions(self):
        tick = [0]
        with patch.dict(G, inspect=MagicMock(side_effect=FileNotFoundError()), refresh_endpoint=MagicMock(), restore_dns=MagicMock(), log=MagicMock()), patch('time.monotonic',side_effect=lambda:tick[0]), patch('time.sleep',side_effect=lambda n:tick.__setitem__(0,tick[0]+n)):
            M['watch'](20,True,True)
            G['refresh_endpoint'].assert_not_called();G['restore_dns'].assert_not_called()

class InstallerTests(unittest.TestCase):
    def test_interface_rendering_and_python_compatibility(self):
        installer = runpy.run_path(str(Path(__file__).with_name('install.py')))
        for interface in ('amn0', 'awg1', 'vpn-office'):
            with self.subTest(interface=interface):
                rendered = installer['render'](interface)
                source = rendered['amnezia-route-repair.py']
                self.assertIn(f"Path('/run/amneziawg/{interface}.sock')", source)
                self.assertIn(f"Path('/sys/class/net/{interface}')", source)
                ast.parse(source, feature_version=(3, 10))
                self.assertEqual(len(rendered), 3)

    def test_invalid_interface_is_rejected(self):
        installer = runpy.run_path(str(Path(__file__).with_name('install.py')))
        for interface in ('', 'lo', '.', '..', '../bad', 'x;id', 'a' * 16):
            with self.subTest(interface=interface), self.assertRaises(ValueError):
                installer['render'](interface)

if __name__ == '__main__':
    unittest.main(verbosity=2)
