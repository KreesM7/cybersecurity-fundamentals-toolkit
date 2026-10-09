import importlib
import math
import unittest


class PasswordTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module("toolkit.modules.password_strength")
        except ModuleNotFoundError:
            self.fail("The password report has not been implemented.")

    def test_common_and_repeated_passwords_are_weak(self):
        module = self.module()
        common = module.analyze_password("password")
        repeated = module.analyze_password("aaaaaaaaaaaa")
        self.assertTrue(common.common)
        self.assertLessEqual(common.score, 1)
        self.assertLess(repeated.bits, 20)
        self.assertGreater(module.analyze_password("qV7!rM2#nT9@zL4$").bits, repeated.bits)

    def test_estimate_rates_and_report_do_not_retain_password(self):
        module = self.module()
        password = "correct horse battery staple"
        result = module.analyze_password(password)
        self.assertAlmostEqual(result.bits, math.log2(result.guesses))
        self.assertEqual(result.times["Online (10/s)"], result.guesses / 10)
        self.assertEqual(result.times["Offline (10,000/s)"], result.guesses / 10000)
        self.assertNotIn(password, repr(result))

    def test_empty_and_overlong_input_are_rejected_without_echo(self):
        module = self.module()
        for password in ["", "x" * 73]:
            with self.assertRaises(ValueError) as caught:
                module.analyze_password(password)
            if password:
                self.assertNotIn(password, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
