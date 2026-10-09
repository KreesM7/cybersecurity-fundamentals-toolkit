import importlib
import unittest


class TargetTests(unittest.TestCase):
    def security(self):
        try:
            return importlib.import_module("toolkit.security")
        except ModuleNotFoundError:
            self.fail("The target restrictions have not been implemented.")

    def test_accepts_local_and_public_web_targets(self):
        security = self.security()
        for url, ip in [
            ("http://localhost:8000/a", "127.0.0.1"),
            ("https://192.168.1.2/", "192.168.1.2"),
            ("http://[::1]/", "::1"),
            ("http://[fd00::1]/", "fd00::1"),
            ("https://93.184.216.34/", "93.184.216.34"),
            ("https://[2606:4700:4700::1111]/", "2606:4700:4700::1111"),
        ]:
            self.assertEqual(security.validate_url(url).ip, ip)
        target = security.validate_url("https://EXAMPLE.COM/search")
        self.assertEqual(target.host, "example.com")
        self.assertIsNone(target.ip)
        self.assertEqual(target.url, "https://example.com/search")
        for url in [
            "file:///x",
            "http://0.0.0.0/",
            "http://169.254.169.254/",
            "http://224.0.0.1/",
            "http://127.1/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://127.1./",
            "http://１２７.１/",
            "http://0x7f000001./",
            "http://0300.0250.0001.0001/",
            "http://user:pass@localhost/",
            "http://bad_host.test/",
            "http://-bad.test/",
            "http://[fe80::1]/",
            "http://[::ffff:8.8.8.8]/",
            "http://[fe80::1%25eth0]/",
            "http://localhost:0/",
            "http://192.168.1.1:65536/",
            "http://localhost/\r\nx",
        ]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                security.validate_url(url)

    def test_custom_subnets_accept_public_targets_and_keep_size_and_address_limits(self):
        security = self.security()
        for value, expected in [
            ("93.184.216.34", "93.184.216.34/32"),
            ("93.184.216.0/24", "93.184.216.0/24"),
            ("10.2.3.0/24", "10.2.3.0/24"),
        ]:
            self.assertEqual(str(security.validate_subnet(value)), expected)
        for value in [
            "93.184.216.0/23",
            "93.184.216.1/24",
            "0.0.0.0/32",
            "224.0.0.0/24",
            "169.254.169.254/32",
            "255.255.255.255/32",
            "::1/128",
            "93.184.216.34; --script=all",
        ]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                security.validate_subnet(value)

    def test_subnet_must_belong_to_selected_private_interface(self):
        security = self.security()
        self.assertEqual(
            str(security.validate_subnet("192.168.1.0/24", "192.168.1.5", "255.255.255.0")),
            "192.168.1.0/24",
        )
        for subnet in [
            "8.8.8.0/24",
            "192.168.2.0/24",
            "192.168.0.0/16",
            "192.168.1.0/23",
            "127.0.0.0/24",
            "10.0.0.0/8",
            "::1/128",
            "192.168.1.1; --script=all",
        ]:
            with self.subTest(subnet=subnet), self.assertRaises(ValueError):
                security.validate_subnet(subnet, "192.168.1.5", "255.255.255.0")

    def test_form_action_must_stay_on_origin(self):
        security = self.security()
        base = security.validate_url("http://localhost:8000/form")
        self.assertEqual(security.validate_form_action(base, "/search").path, "/search")
        for action in [
            "http://8.8.8.8/",
            "http://192.168.1.2/",
            "//localhost:8001/",
            "https://localhost:8000/",
        ]:
            with self.subTest(action=action), self.assertRaises(ValueError):
                security.validate_form_action(base, action)
        public = security.validate_url("https://example.com/form")
        self.assertEqual(
            security.validate_form_action(public, "/search").url, "https://example.com/search"
        )
        for action in [
            "https://other.test/search",
            "http://example.com/search",
            "https://example.com:8443/search",
        ]:
            with self.subTest(action=action), self.assertRaises(ValueError):
                security.validate_form_action(public, action)


if __name__ == "__main__":
    unittest.main()
