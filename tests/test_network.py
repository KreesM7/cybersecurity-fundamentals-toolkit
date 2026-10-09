import importlib
import socket
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch


class NetworkTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module("toolkit.modules.network_scanner")
        except ModuleNotFoundError:
            self.fail("The local network module has not been implemented.")

    def test_interfaces_exclude_public_and_down_adapters(self):
        module = self.module()

        def address(ip):
            return SimpleNamespace(family=socket.AF_INET, address=ip, netmask="255.255.255.0")

        with (
            patch(
                "psutil.net_if_addrs",
                return_value={
                    "LAN": [address("192.168.1.5")],
                    "Public": [address("8.8.8.8")],
                    "Down": [address("10.0.0.1")],
                },
            ),
            patch(
                "psutil.net_if_stats",
                return_value={
                    name: SimpleNamespace(isup=name != "Down") for name in ["LAN", "Public", "Down"]
                },
            ),
        ):
            self.assertEqual([i.name for i in module.list_interfaces()], ["LAN"])

    def test_filtered_results_do_not_claim_live_host(self):
        module = self.module()
        reply = {
            "scan": {
                "192.168.1.9": {
                    "status": {"state": "up", "reason": "user-set"},
                    "tcp": {80: {"state": "filtered", "reason": "no-response"}},
                }
            }
        }
        result = module.interpret_host("192.168.1.9", reply)
        self.assertEqual(result.status, "Inconclusive")
        self.assertEqual(result.open_ports, [])
        reply["scan"]["192.168.1.9"]["tcp"][80]["state"] = "closed"
        reply["scan"]["192.168.1.9"]["tcp"][80]["reason"] = "conn-refused"
        self.assertEqual(module.interpret_host("192.168.1.9", reply).status, "Responded")

    def test_rejects_stale_interface_before_nmap(self):
        module = self.module()
        interface = module.NetworkInterface("LAN", "192.168.1.5", "255.255.255.0")
        with patch.object(module, "list_interfaces", return_value=[]):
            with self.assertRaisesRegex(ValueError, "interface"):
                module.scan_subnet("192.168.1.0/24", interface, authorized=True)

    def test_scan_uses_fixed_connect_arguments_and_real_xml_parser(self):
        module = self.module()
        interface = module.NetworkInterface("LAN", "192.168.1.5", "255.255.255.0")
        xml = b"""<nmaprun args="fixture"><scaninfo type="connect" protocol="tcp" services="80"/>
          <host><status state="up" reason="user-set"/><address addr="192.168.1.9" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
          <service name="http"/></port></ports></host>
          <runstats><finished timestr="fixture" elapsed="0.1"/>
          <hosts up="1" down="0" total="1"/></runstats></nmaprun>"""
        with (
            patch.object(module, "list_interfaces", return_value=[interface]),
            patch.object(module, "nmap_path", return_value="fixture-nmap.exe"),
            patch(
                "subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=xml, stderr=b"")
            ) as run,
        ):
            result = module.scan_subnet("192.168.1.9/32", interface, authorized=True)
        self.assertEqual(result[0].status, "Responded")
        self.assertEqual(result[0].open_ports, ["80/tcp (http)"])
        args, options = run.call_args
        self.assertIn("-sT", args[0])
        self.assertIn("-n", args[0])
        self.assertNotIn("--script", args[0])
        self.assertEqual(options["timeout"], 8)
        self.assertFalse(options["shell"])
        self.assertEqual(options["creationflags"], getattr(subprocess, "CREATE_NO_WINDOW", 0))

    def test_custom_public_target_uses_system_routing_and_real_xml_parser(self):
        module = self.module()
        xml = b"""<nmaprun args="fixture"><scaninfo type="connect" protocol="tcp" services="80"/>
          <host><status state="up" reason="user-set"/>
          <address addr="93.184.216.34" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
          <service name="http"/></port></ports></host>
          <runstats><finished timestr="fixture" elapsed="0.1"/>
          <hosts up="1" down="0" total="1"/></runstats></nmaprun>"""
        with (
            patch.object(
                module,
                "list_interfaces",
                side_effect=AssertionError("Custom routing needs no LAN adapter"),
            ),
            patch.object(module, "nmap_path", return_value="fixture-nmap.exe"),
            patch(
                "subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=xml, stderr=b"")
            ) as run,
        ):
            results = module.scan_subnet("93.184.216.34", authorized=True)
        self.assertEqual(results[0].ip, "93.184.216.34")
        self.assertEqual(results[0].status, "Responded")
        self.assertIn("93.184.216.34", run.call_args.args[0])

    def test_ownership_and_invalid_custom_targets_stop_before_nmap(self):
        module = self.module()
        with patch("subprocess.run", side_effect=AssertionError("No scan should start")):
            with self.assertRaisesRegex(ValueError, "permission|authorize|own"):
                module.scan_subnet("93.184.216.34")
            for target in ("93.184.216.0/23", "224.0.0.1", "::1"):
                with self.subTest(target=target), self.assertRaises(ValueError):
                    module.scan_subnet(target, authorized=True)


if __name__ == "__main__":
    unittest.main()
