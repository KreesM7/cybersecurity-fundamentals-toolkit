import importlib
import unittest


class TargetTests(unittest.TestCase):
    def security(self):
        try:
            return importlib.import_module('toolkit.security')
        except ModuleNotFoundError:
            self.fail('The target restrictions have not been implemented.')

    def test_accepts_only_literal_local_web_targets(self):
        security = self.security()
        for url, ip in [('http://localhost:8000/a', '127.0.0.1'),
                        ('https://192.168.1.2/', '192.168.1.2'),
                        ('http://[::1]/', '::1'), ('http://[fd00::1]/', 'fd00::1')]:
            self.assertEqual(security.validate_url(url).ip, ip)
        for url in ['http://8.8.8.8/', 'http://example.com/', 'file:///x',
                    'http://0.0.0.0/', 'http://169.254.169.254/', 'http://224.0.0.1/',
                    'http://127.1/', 'http://2130706433/', 'http://user:pass@localhost/',
                    'http://[::ffff:8.8.8.8]/', 'http://[fe80::1%25eth0]/',
                    'http://localhost:0/', 'http://192.168.1.1:65536/', 'http://localhost/\r\nx']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                security.validate_url(url)

    def test_subnet_must_belong_to_selected_private_interface(self):
        security = self.security()
        self.assertEqual(str(security.validate_subnet('192.168.1.0/24', '192.168.1.5', '255.255.255.0')),
                         '192.168.1.0/24')
        for subnet in ['8.8.8.0/24', '192.168.2.0/24', '192.168.0.0/16',
                       '192.168.1.0/23', '127.0.0.0/24', '10.0.0.0/8', '::1/128',
                       '192.168.1.1; --script=all']:
            with self.subTest(subnet=subnet), self.assertRaises(ValueError):
                security.validate_subnet(subnet, '192.168.1.5', '255.255.255.0')

    def test_form_action_must_stay_on_origin(self):
        security = self.security()
        base = security.validate_url('http://localhost:8000/form')
        self.assertEqual(security.validate_form_action(base, '/search').path, '/search')
        for action in ['http://8.8.8.8/', 'http://192.168.1.2/', '//localhost:8001/', 'https://localhost:8000/']:
            with self.subTest(action=action), self.assertRaises(ValueError):
                security.validate_form_action(base, action)


if __name__ == '__main__':
    unittest.main()
