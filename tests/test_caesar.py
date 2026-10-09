import importlib
import unittest


class CaesarTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module("toolkit.modules.caesar")
        except ModuleNotFoundError:
            self.fail("The Caesar module has not been implemented.")

    def test_preserves_non_ascii_case_and_punctuation(self):
        module = self.module()
        self.assertEqual(module.transform("Az, café!\n123", 1), "Ba, dbgé!\n123")
        self.assertEqual(module.transform("Ba, dbgé!\n123", 1, decrypt=True), "Az, café!\n123")

    def test_round_trips_every_shift_and_brute_force_contains_plaintext(self):
        module = self.module()
        for shift in range(1, 26):
            encrypted = module.transform("Hello, World!", shift)
            self.assertEqual(module.transform(encrypted, shift, decrypt=True), "Hello, World!")
            self.assertIn((shift, "Hello, World!"), module.brute_force(encrypted))
        self.assertEqual(len(module.brute_force("Khoor")), 25)

    def test_shift_out_of_range_is_rejected(self):
        module = self.module()
        for shift in [0, 26, -1, 1.5, True]:
            with self.assertRaises(ValueError):
                module.transform("x", shift)


if __name__ == "__main__":
    unittest.main()
