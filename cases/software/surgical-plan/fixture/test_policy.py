import unittest

from policy import may_retry


class RetryPolicyTests(unittest.TestCase):
    def test_boundary(self):
        self.assertTrue(may_retry(2))
        self.assertFalse(may_retry(3))


if __name__ == "__main__":
    unittest.main()
