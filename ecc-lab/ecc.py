"""Educational elliptic-curve library (short Weierstrass y^2 = x^3 + ax + b over GF(p)).
NOT constant-time and NOT for production use."""
import hashlib
import secrets

CURVES = {
    # Tiny textbook curve: 19 points, G=(5,1) has prime order 19. Good for visualising.
    "toy17": dict(p=17, a=2, b=2, G=(5, 1), n=19),
    "secp256k1": dict(
        p=2**256 - 2**32 - 977, a=0, b=7,
        G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
           0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
        n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141),
}


class Curve:
    """Points are (x, y) tuples; the point at infinity is None."""

    def __init__(self, name):
        c = CURVES[name]
        self.name, self.p, self.a, self.b = name, c["p"], c["a"], c["b"]
        self.G, self.n = c["G"], c["n"]

    def on_curve(self, P):
        if P is None:
            return True
        x, y = P
        return 0 <= x < self.p and 0 <= y < self.p and (y * y - (x**3 + self.a * x + self.b)) % self.p == 0

    def neg(self, P):
        return None if P is None else (P[0], (-P[1]) % self.p)

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        (x1, y1), (x2, y2) = P, Q
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None  # P + (-P) = O
        if P == Q:
            m = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.p) % self.p
        else:
            m = (y2 - y1) * pow(x2 - x1, -1, self.p) % self.p
        x3 = (m * m - x1 - x2) % self.p
        return (x3, (m * (x1 - x3) - y1) % self.p)

    def mul(self, k, P):
        """Double-and-add scalar multiplication."""
        if k < 0:
            k, P = -k, self.neg(P)
        R = None
        while k:
            if k & 1:
                R = self.add(R, P)
            P = self.add(P, P)
            k >>= 1
        return R

    def keygen(self):
        d = 1 + secrets.randbelow(self.n - 1)
        return d, self.mul(d, self.G)

    def ecdh(self, d, Q):
        if Q is None or not self.on_curve(Q):
            raise ValueError("invalid public key (infinity or not on curve)")
        S = self.mul(d, Q)
        if S is None:
            raise ValueError("shared secret is the point at infinity")
        return S[0]

    def hash_to_int(self, msg):
        z = int.from_bytes(hashlib.sha256(msg.encode()).digest(), "big")
        extra = 256 - self.n.bit_length()
        return z >> extra if extra > 0 else z

    def sign(self, d, msg, k=None):
        """ECDSA. `k` is only exposed so tests can demonstrate nonce reuse."""
        z = self.hash_to_int(msg)
        while True:
            kk = k if k is not None else 1 + secrets.randbelow(self.n - 1)
            R = self.mul(kk, self.G)
            r = R[0] % self.n
            s = pow(kk, -1, self.n) * (z + r * d) % self.n
            if r and s:
                return r, s
            if k is not None:
                raise ValueError("bad nonce")

    def verify(self, Q, msg, sig):
        r, s = sig
        if Q is None or not self.on_curve(Q):
            return False
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False
        z, w = self.hash_to_int(msg), pow(s, -1, self.n)
        X = self.add(self.mul(z * w % self.n, self.G), self.mul(r * w % self.n, Q))
        return X is not None and X[0] % self.n == r
