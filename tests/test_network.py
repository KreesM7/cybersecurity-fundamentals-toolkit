import importlib
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import socket


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


if __name__ == '__main__':
    unittest.main()
