import importlib
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import socket
import subprocess


class NetworkTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('toolkit.modules.network_scanner')
        except ModuleNotFoundError:
            self.fail('The local network module has not been implemented.')

    def test_interfaces_exclude_public_and_down_adapters(self):
        module = self.module()
        address = lambda ip: SimpleNamespace(family=socket.AF_INET, address=ip, netmask='255.255.255.0')
        with patch('psutil.net_if_addrs', return_value={'LAN': [address('192.168.1.5')],
                   'Public': [address('8.8.8.8')], 'Down': [address('10.0.0.1')]}), \
             patch('psutil.net_if_stats', return_value={name: SimpleNamespace(isup=name != 'Down')
                                                       for name in ['LAN', 'Public', 'Down']}):
            self.assertEqual([i.name for i in module.list_interfaces()], ['LAN'])

    def test_filtered_results_do_not_claim_live_host(self):
        module = self.module()
        reply = {'scan': {'192.168.1.9': {'status': {'state': 'up', 'reason': 'user-set'},
                 'tcp': {80: {'state': 'filtered', 'reason': 'no-response'}}}}}
        result = module.interpret_host('192.168.1.9', reply)
        self.assertEqual(result.status, 'Inconclusive')
        self.assertEqual(result.open_ports, [])
        reply['scan']['192.168.1.9']['tcp'][80]['state'] = 'closed'
        reply['scan']['192.168.1.9']['tcp'][80]['reason'] = 'conn-refused'
        self.assertEqual(module.interpret_host('192.168.1.9', reply).status, 'Responded')

    def test_rejects_stale_interface_before_nmap(self):
        module = self.module()
        interface = module.NetworkInterface('LAN', '192.168.1.5', '255.255.255.0')
        with patch.object(module, 'list_interfaces', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'interface'):
                module.scan_subnet('192.168.1.0/24', interface)

    def test_scan_uses_fixed_connect_arguments_and_real_xml_parser(self):
        module = self.module()
        interface = module.NetworkInterface('LAN', '192.168.1.5', '255.255.255.0')
        xml = b'''<nmaprun args="fixture"><scaninfo type="connect" protocol="tcp" services="80"/>
          <host><status state="up" reason="user-set"/><address addr="192.168.1.9" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
          <service name="http"/></port></ports></host>
          <runstats><finished timestr="fixture" elapsed="0.1"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''
        with patch.object(module, 'list_interfaces', return_value=[interface]), \
             patch.object(module, 'nmap_path', return_value='fixture-nmap.exe'), \
             patch('subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=xml, stderr=b'')) as run:
            result = module.scan_subnet('192.168.1.9/32', interface)
        self.assertEqual(result[0].status, 'Responded')
        self.assertEqual(result[0].open_ports, ['80/tcp (http)'])
        args, options = run.call_args
        self.assertIn('-sT', args[0])
        self.assertIn('-n', args[0])
        self.assertNotIn('--script', args[0])
        self.assertEqual(options['timeout'], 8)
        self.assertFalse(options['shell'])
        self.assertEqual(options['creationflags'], getattr(subprocess, 'CREATE_NO_WINDOW', 0))


if __name__ == '__main__':
    unittest.main()
