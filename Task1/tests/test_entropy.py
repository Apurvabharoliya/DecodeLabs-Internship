import unittest
from app.entropy import calculate_entropy, calculate_pool_size

class TestEntropy(unittest.TestCase):
    def test_pool_size(self):
        self.assertEqual(calculate_pool_size("a"), 26)
        self.assertEqual(calculate_pool_size("aA"), 52)
        self.assertEqual(calculate_pool_size("aA1"), 62)
        self.assertEqual(calculate_pool_size("aA1!"), 94)

    def test_entropy(self):
        # pool of 26, length 1 => ~4.7 bits
        self.assertAlmostEqual(calculate_entropy("a"), 4.700439718141092, places=5)
        # pool of 62, length 5 => ~29.7 bits
        self.assertAlmostEqual(calculate_entropy("aA1b2"), 29.770984852959883, places=5)

if __name__ == "__main__":
    unittest.main()
