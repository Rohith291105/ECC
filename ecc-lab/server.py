"""JSON API + static file server (standard library only). Run: python server.py"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from ecc import CURVES, Curve

HERE = os.path.dirname(os.path.abspath(__file__))


def num(v):
    s = str(v).strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def fmt(c, v):
    return str(v) if c.p < 1000 else hex(v)


def pt_in(c, o):
    if not o or o.get("inf"):
        return None
    P = (num(o["x"]), num(o["y"]))
    if not c.on_curve(P):
        raise ValueError(f"point {P} is not on {c.name}")
    return P


def pt_out(c, P):
    return {"inf": True} if P is None else {"x": fmt(c, P[0]), "y": fmt(c, P[1])}


def get_curve(d):
    return Curve(d.get("curve", "toy17"))


def api_keygen(d):
    c = get_curve(d)
    k, Q = c.keygen()
    return {"priv": fmt(c, k), "pub": pt_out(c, Q)}


def api_add(d):
    c = get_curve(d)
    return {"result": pt_out(c, c.add(pt_in(c, d.get("P")), pt_in(c, d.get("Q"))))}


def api_mul(d):
    c = get_curve(d)
    P = pt_in(c, d["P"]) if d.get("P") else c.G
    return {"result": pt_out(c, c.mul(num(d["k"]), P))}


def api_oncurve(d):
    c = get_curve(d)
    o = d.get("P") or {}
    return {"on_curve": c.on_curve(None if o.get("inf") else (num(o["x"]), num(o["y"])))}


def api_ecdh(d):
    c = get_curve(d)
    return {"shared_x": fmt(c, c.ecdh(num(d["priv"]), pt_in(c, d["pub"])))}


def api_sign(d):
    c = get_curve(d)
    r, s = c.sign(num(d["priv"]), d["msg"])
    return {"r": fmt(c, r), "s": fmt(c, s)}


def api_verify(d):
    c = get_curve(d)
    sig = (num(d["sig"]["r"]), num(d["sig"]["s"]))
    return {"valid": c.verify(pt_in(c, d["pub"]), d["msg"], sig)}


ROUTES = {"/api/keygen": api_keygen, "/api/add": api_add, "/api/mul": api_mul,
          "/api/oncurve": api_oncurve, "/api/ecdh": api_ecdh,
          "/api/sign": api_sign, "/api/verify": api_verify}


class Handler(BaseHTTPRequestHandler):
    def send(self, code, body, ctype="application/json"):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/api/curves":
            out = []
            for name in CURVES:
                c = Curve(name)
                out.append({"name": name, "p": fmt(c, c.p), "a": c.a, "b": c.b, "n": fmt(c, c.n),
                            "G": pt_out(c, c.G), "small": c.p < 1000})
            self.send(200, out)
        elif u.path == "/api/points":
            try:
                c = Curve(parse_qs(u.query).get("curve", ["toy17"])[0])
                if c.p >= 1000:
                    raise ValueError("curve too large to enumerate")
                pts = [{"x": x, "y": y} for x in range(c.p) for y in range(c.p) if c.on_curve((x, y))]
                self.send(200, pts)
            except (KeyError, ValueError) as e:
                self.send(400, {"error": str(e)})
        elif u.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "static", "index.html"), "rb") as f:
                self.send(200, f.read(), "text/html; charset=utf-8")
        else:
            self.send(404, {"error": "not found"})

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n) or b"{}")
            self.send(200, ROUTES[self.path](data))
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            self.send(400, {"error": f"{type(e).__name__}: {e}"})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"ECC Lab running at http://127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
