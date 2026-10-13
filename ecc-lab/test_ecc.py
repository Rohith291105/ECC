import unittest
from ecc import Curve

K, T = Curve("secp256k1"), Curve("toy17")


class TestCore(unittest.TestCase):
    def test_generators_on_curve(self):
        for c in (K, T):
            self.assertTrue(c.on_curve(c.G))

    def test_order_of_G(self):
        for c in (K, T):
            self.assertIsNone(c.mul(c.n, c.G))

    def test_known_vector_2G(self):
        x = 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
        y = 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A
        self.assertEqual(K.mul(2, K.G), (x, y))
        self.assertEqual(K.add(K.G, K.G), (x, y))

    def test_toy_group_is_cyclic_of_order_19(self):
        pts = {T.mul(k, T.G) for k in range(1, 19)}
        self.assertEqual(len(pts), 18)
        self.assertTrue(all(T.on_curve(p) for p in pts))
        self.assertIsNone(T.mul(19, T.G))

    def test_identity_and_inverse(self):
        P = K.mul(12345, K.G)
        self.assertEqual(K.add(P, None), P)
        self.assertIsNone(K.add(P, K.neg(P)))

    def test_scalar_distributes(self):
        a, b = 987654321, 123456789
        self.assertEqual(K.mul(a + b, K.G), K.add(K.mul(a, K.G), K.mul(b, K.G)))

    def test_negative_and_zero_scalar(self):
        self.assertEqual(K.mul(-3, K.G), K.neg(K.mul(3, K.G)))
        self.assertIsNone(K.mul(0, K.G))


class TestProtocols(unittest.TestCase):
    def test_ecdh_agreement(self):
        a, A = K.keygen()
        b, B = K.keygen()
        self.assertEqual(K.ecdh(a, B), K.ecdh(b, A))

    def test_ecdh_rejects_invalid_curve_point(self):
        with self.assertRaises(ValueError):
            K.ecdh(5, (1, 1))
        with self.assertRaises(ValueError):
            K.ecdh(5, None)

    def test_sign_verify(self):
        d, Q = K.keygen()
        sig = K.sign(d, "hello")
        self.assertTrue(K.verify(Q, "hello", sig))
        self.assertFalse(K.verify(Q, "hellp", sig))
        _, Q2 = K.keygen()
        self.assertFalse(K.verify(Q2, "hello", sig))

    def test_verify_rejects_out_of_range_and_bad_keys(self):
        d, Q = K.keygen()
        r, s = K.sign(d, "m")
        for bad in [(0, s), (r, 0), (K.n, s), (r, K.n)]:
            self.assertFalse(K.verify(Q, "m", bad))
        self.assertFalse(K.verify(None, "m", (r, s)))
        self.assertFalse(K.verify((1, 1), "m", (r, s)))

    def test_nonce_reuse_leaks_private_key(self):
        d, _ = K.keygen()
        k = 0xC0FFEE
        (r, s1), (_, s2) = K.sign(d, "msg one", k), K.sign(d, "msg two", k)
        z1, z2 = K.hash_to_int("msg one"), K.hash_to_int("msg two")
        k_rec = (z1 - z2) * pow(s1 - s2, -1, K.n) % K.n
        d_rec = (s1 * k_rec - z1) * pow(r, -1, K.n) % K.n
        self.assertEqual(d_rec, d)


if __name__ == "__main__":
    unittest.main()
